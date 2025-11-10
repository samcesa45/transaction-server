import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { TransactionsDto } from './dto/transactionsdto';
import { Decimal } from '@prisma/client/runtime/client';

const DAILY_LIMIT = new Decimal(100000);
const SINGLE_TRANSFER_LIMIT = new Decimal(10000);
@Injectable()
export class TransactionsService {
  constructor(private prisma: PrismaService) {}
  /**
   * Performs an atomic intrabank transfer: Debit, Credit, and Record Creation.
   * This is wrapped in a Prisma $transaction to ensure ACID properties.
   * * @param dto - Transfer details (source, destination, amount)
   * @param userId - ID of the authenticated user (for security checks)
   * @returns The created transaction record
   */
  async intrabankTransfer(dto: TransactionsDto, userId: string) {
    const amountDecimal = new Decimal(dto.amount);

    return this.prisma.$transaction(async (tx) => {
      //validate source account ownership and existence
      const userAccounts = await tx.account.findMany({
        where: { userId },
      });

      if (!userAccounts || userAccounts.length === 0) {
        throw new NotFoundException('No accounts found for this user.');
      }

      let sourceAccount;

      if (dto.sourceAccountNumber) {
        sourceAccount = userAccounts.find(
          (acc) => acc.accountNumber === dto.sourceAccountNumber,
        );
        if (!sourceAccount) {
          throw new NotFoundException(
            'Source account not found or does not belong to you.',
          );
        }
      } else {
        sourceAccount = userAccounts[0];
      }

      if (sourceAccount.balance.lessThan(amountDecimal)) {
        throw new BadRequestException(
          'Insufficient funds in the source account.',
        );
      }

      if (amountDecimal.greaterThan(SINGLE_TRANSFER_LIMIT)) {
        throw new BadRequestException(
          `Transfer amount exceeds limit of ₦${SINGLE_TRANSFER_LIMIT.toFixed(2)}`,
        );
      }

      const destinationAccount = await tx.account.findUnique({
        where: { accountNumber: dto.destinationAccountNumber },
      });

      if (!destinationAccount) {
        throw new NotFoundException('Destination account not found.');
      }

      if (sourceAccount.id === destinationAccount.id) {
        throw new BadRequestException(
          'Cannot transfer funds to thesame account.',
        );
      }

      //debit source account
      await tx.account.update({
        where: { id: sourceAccount.id },
        data: { balance: { decrement: amountDecimal } },
      });

      //credit destination account
      await tx.account.update({
        where: { id: destinationAccount.id },
        data: { balance: { increment: amountDecimal } },
      });

      //check daily limit
      const today = new Date();
      today.setHours(0, 0, 0);

      const dailyTotal = await tx.transaction.aggregate({
        where: {
          sourceAccountId: sourceAccount.id,
          createdAt: { gte: today },
          status: 'completed',
        },
        _sum: { amount: true },
      });

      const totalToday = new Decimal(dailyTotal._sum.amount || 0);
      if (totalToday.plus(amountDecimal).greaterThan(DAILY_LIMIT)) {
        throw new BadRequestException('Daily transfer limit exceeded');
      }
      //create transaction record
      const transaction = await tx.transaction.create({
        data: {
          sourceAccountId: sourceAccount.id,
          destinationAccountId: destinationAccount.id,
          amount: amountDecimal,
          reference: dto.reference || 'INTRABANK_TRANSFER',
          narration: dto.narration || 'transfer',
          status: 'completed',
        },
        include: {
          sourceAccount: {
            select: {
              accountNumber: true,
              User: {
                select: {
                  firstName: true,
                  lastName: true,
                },
              },
            },
          },
          destinationAccount: {
            select: {
              accountNumber: true,
              User: {
                select: {
                  firstName: true,
                  lastName: true,
                },
              },
            },
          },
        },
      });

      // TODO: Asynchronously notify the client via WebSockets/Firebase here
      // This part would typically be handled by an event/message queue after the transaction commits.

      return transaction;
    });
  }

  async lookupAccount(accountNumber: string) {
    const account = await this.prisma.account.findUnique({
      where: { accountNumber },
      select: {
        accountNumber: true,
        User: {
          select: {
            firstName: true,
            lastName: true,
          },
        },
      },
    });

    if (!account) {
      throw new NotFoundException('Account not found');
    }
    return {
      accountNumber: account.accountNumber,
      accountName: `${account.User?.firstName} ${account.User?.lastName}`,
    };
  }

  async getTransactionHistory(
    accountId: string,
    page: number = 1,
    limit: number = 20,
  ) {
    const skip = (page - 1) * limit;

    //retrieve transactions where the account is either the source or destination
    const transactions = await this.prisma.transaction.findMany({
      where: {
        OR: [
          { sourceAccountId: accountId },
          { destinationAccountId: accountId },
        ],
      },
      orderBy: { createdAt: 'desc' },
      skip: skip,
      take: limit,
    });

    const total = await this.prisma.transaction.count({
      where: {
        OR: [
          { sourceAccountId: accountId },
          { destinationAccountId: accountId },
        ],
      },
    });

    return {
      data: transactions,
      meta: {
        total,
        page,
        limit,
        lastPage: Math.ceil(total / limit),
      },
    };
  }
}
