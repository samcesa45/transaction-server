import { BadRequestException, ForbiddenException, Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { TransactionsDto } from './dto/transactionsdto';
import { Decimal } from 'generated/prisma/runtime/library';

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
  async intrabankTransfer(dto:TransactionsDto, userId:string) {
    const amountDecimal = new Decimal(dto.amount);
    
    // IMPORTANT: All operations MUST be wrapped in a single transaction
    return this.prisma.$transaction(async (tx) => {
        //validate source account ownership and existence
        const sourceAccount = await tx.account.findUnique({
            where: { id: dto.sourceAccountId }
        });

        if (!sourceAccount) {
            throw new NotFoundException('Source account not found.');
        }

        if (sourceAccount.userId !== userId) {
            throw new ForbiddenException('Access denied to source account.')
        }
        if (sourceAccount.balance.lessThan(amountDecimal)) {
            throw new BadRequestException('Insufficient funds in the source account.')
        }
        if (sourceAccount.id === dto.destinationAccountId) {
            throw new BadRequestException('Cannot transfer funds to thesame account.')
        }

        //validate destination account existence
        const destinationAccount = await tx.account.findUnique({
            where: {id: dto.destinationAccountId}
        });

        if (!destinationAccount) {
            throw new NotFoundException('Destination account not found.');
        }

        //debit source account
        await tx.account.update({
            where: { id: dto.sourceAccountId},
            data: { balance: {decrement: amountDecimal}}
        });

        //credit destination account
        await tx.account.update({
            where: { id: dto.destinationAccountId },
            data: { balance : { increment: amountDecimal }}
        });

        //create transaction record
        const transaction = await tx.transaction.create({
            data: {
                sourceAccountId: dto.sourceAccountId,
                destinationAccountId: dto.destinationAccountId,
                amount: amountDecimal,
                reference: dto.reference || 'INTRABANK_TRANSFER',
                status: 'SUCCESS'
            }
        });

        // TODO: Asynchronously notify the client via WebSockets/Firebase here
       // This part would typically be handled by an event/message queue after the transaction commits.

        return transaction;
    })
  }

  async getTransactionHistory(accountId:string, page: number = 1, limit: number = 20) {
    const skip = (page - 1) * limit;

    //retrieve transactions where the account is either the source or destination
    const transactions = await this.prisma.transaction.findMany({
        where: {
            OR: [
                { sourceAccountId: accountId },
                { destinationAccountId: accountId }
            ],
        },
        orderBy: { date: 'desc' },
        skip: skip,
        take: limit,
    });

    const total = await this.prisma.transaction.count({
        where: {
            OR: [
                { sourceAccountId: accountId },
                { destinationAccountId: accountId }
            ]
        }
    });

    return {
        data: transactions,
        meta: {
            total,
            page,
            limit,
            lastPage: Math.ceil(total / limit)
        }
    }
  }
}
