import {Account, PrismaClient, User} from '@prisma/client';
import { faker }  from '@faker-js/faker';
import bcrypt from 'bcrypt'

const prisma = new PrismaClient();

const CONFIG = {
    USERS_COUNT: 10,
    ACCOUNTS_PER_USER: {min: 1, max: 3},
    TRANSACTIONS_PER_ACCOUNT: { min: 5, max: 15},
    INITIAL_BALANCE : { min: 5000, max: 500000 },
    TRANSACTION_AMOUNT : { min: 100, max: 50000 },
    DEFAULT_PASSWORD: "Password123",
    SALT_ROUNDS: 10,
    TRANSACTION_DAYS_BACK: 90
} as const; 

const PHONE_PREFIXES = ['070', '080', '081', '090', '091'] as const;
const ACCOUNT_TYPES = ['savings', 'current'] as const;
const TRANSACTION_TYPES = ['credit', 'debit'] as const;
const TRANSACTION_REFERENCES = [
    'Airtime Purchase',
    'Transfer to Savings',
    'POS Withdrawal',
    'Bill Payment',
    'Transfer from Friend',
    'Salary Credit',
    'Online Shopping',
    'Restaurant Payment',
    'Uber Ride',
    'Subscription Fee',
] as const;

function generatePhoneNumber(): string {
    const prefix = faker.helpers.arrayElement([...PHONE_PREFIXES]);
    const rest = faker.string.numeric(8);
    return `${prefix}${rest}`;
}

function generateAccountNumber(): string {
    return faker.string.numeric(10)
}

function generateEmail(firstName: string, lastName: string):string {
    return `${firstName.toLowerCase()}.${lastName.toLowerCase()}@example.com`
}

async function hashPassword(password:string): Promise<string> {
    return bcrypt.hash(password, CONFIG.SALT_ROUNDS);
}

async function generateUser(passwordHash: string) {
    const firstName = faker.person.firstName();
    const lastName = faker.person.lastName();
    const phoneNumber = generatePhoneNumber();
    const email = generateEmail(firstName, lastName);

    return {
        firstName,
        lastName,
        email,
        phoneNumber,
        passwordHash,
        isActive: true,
    }
}

function generateAccount(userId:string) {
    return {
        userId,
        accountNumber: generateAccountNumber(),
        balance: faker.number.float({
            min: CONFIG.INITIAL_BALANCE.min,
            max: CONFIG.INITIAL_BALANCE.max,
            fractionDigits: 2,
            // precision: 0.01,
        }),
        currency: "NGN",
        accountType: faker.helpers.arrayElement([...ACCOUNT_TYPES]),
    }
}

function generateTransaction(accountId: string) {
    const accountType = faker.helpers.arrayElement([...TRANSACTION_TYPES]);
    const amount = faker.number.float({
        min: CONFIG.TRANSACTION_AMOUNT.min,
        max: CONFIG.TRANSACTION_AMOUNT.max,
        fractionDigits: 2,
        // precision:0.01,
    });

    // For credit transactions, this account receives money (destination)
    // For debit transactions, this account sends money (source)
    const relationField = accountType === 'credit' ? 'destinationAccount' : 'sourceAccount';

    return {
        [relationField]: {
            connect: { id : accountId }
        },
        amount,
        accountType,
        reference: faker.helpers.arrayElement([...TRANSACTION_REFERENCES]),
        date: faker.date.recent({days: CONFIG.TRANSACTION_DAYS_BACK}),
        status: 'completed',
    }
}

async function clearDatabase() {
    console.log('Clearing existing data');
    await prisma.$transaction([
        prisma.transaction.deleteMany(),
        prisma.account.deleteMany(),
        prisma.user.deleteMany(),
    ]);

    console.log('Database cleared successfully');
}

async function seedUsers(count:number, passwordHash: string): Promise<User[]> {
    console.log(`Creating ${count} users`);
    const users: User[] = [];

    for (let i = 0; i < count; i++) {
        const userData = await generateUser(passwordHash);
        const user = await prisma.user.create({ data: userData });
        users.push(user);

        if ((i + 1) % 5 === 0 ) {
            console.log(`Created ${i + 1}/${count} users`)
        }
    }

    console.log(`Created ${users.length} users`);
    return users;
}

async function seedAccounts(userId: string): Promise<Account[]> {
    const accountCount = faker.number.int(CONFIG.ACCOUNTS_PER_USER);
    const accounts: Account[] = [];

    for ( let i = 0; i < accountCount; i++ ) {
        const accountData = generateAccount(userId);
        // const account = await prisma.account.create({ 
        //     data: {
        //     ...accountData,
        //     User: { connect: {id: userId}}
        //     }

        //  });
        const account = await prisma.account.create({
            data: accountData
        })
        accounts.push(account);
    }

    return accounts;
}

async function seedTransactions(accountId: string, allAccountIds: string[]): Promise<number> {
    const transactionCount = faker.number.int(CONFIG.TRANSACTIONS_PER_ACCOUNT);
    const transactions = [];
    
    for (let i = 0; i < transactionCount; i++) {
      const type = faker.helpers.arrayElement([...TRANSACTION_TYPES]);
      const amount = faker.number.float({
        min: CONFIG.TRANSACTION_AMOUNT.min,
        max: CONFIG.TRANSACTION_AMOUNT.max,
        fractionDigits: 2,
      });

      //for credit: money comes into this account (destination)
      //for debit: money goes out of this account (source)
      const sourceAccountId = type === 'debit'
      ? accountId 
      : faker.helpers.arrayElement(allAccountIds);

      const destinationAccountId = type === 'credit'
      ? accountId
      : faker.helpers.arrayElement(allAccountIds);
  
      transactions.push({
        sourceAccountId,
        destinationAccountId,
        amount,
        reference: faker.helpers.arrayElement([...TRANSACTION_REFERENCES]),
        date: faker.date.recent({ days: CONFIG.TRANSACTION_DAYS_BACK }),
        status: 'completed',
      } as never);
  
    }
    
    await prisma.transaction.createMany({
        data: transactions
    });

    return transactions.length;
  }

async function main() {
    console.log('Starting database seeding...\n');
    const startTime = Date.now();

    try {
        //clear existing data
        await clearDatabase();

        //Hash password once for all users
        console.log('Hashing default password...');
        const passwordHash = await hashPassword(CONFIG.DEFAULT_PASSWORD);
        console.log('Password hashed\n');

        //create users
        const users = await seedUsers(CONFIG.USERS_COUNT, passwordHash);

        //create accounts and transactions for each user
        let totalAccounts = 0;
        let totalTransactions = 0;
        const allAccounts: Account[] = [];

        console.log('\n Creating accounts and transactions...');

        for (const [index, user] of users.entries()) {
            const accounts = await seedAccounts(user?.id);
            totalAccounts += accounts.length;
            allAccounts.push(...accounts);

            if ((index + 1) % 3 === 0) {
                console.log(`Processed ${index + 1}/${users.length} users`);
            }
        }

        console.log(`Created ${totalAccounts} accounts`);
        console.log('\n Creating transactions')

        //get all account IDs for transactions
        const allAccountIds = allAccounts.map(acc => acc.id);

        //create transactions foe each account
        for (const [index, account] of allAccounts.entries()) {
            const transactionCount = await seedTransactions(account.id, allAccountIds);
            totalTransactions += transactionCount;

            if ((index + 1) % 10 === 0) {
                console.log(`Created transactions for ${index + 1}/${allAccounts.length} accounts`);
            }
        }

        const duration = ((Date.now() - startTime) / 1000).toFixed(2);

        console.log('\n' + '='.repeat(50));
        console.log('Seeding completed successfully!');
        console.log('='.repeat(50));
        console.log(`Statistics:`)
        console.log(`Users: ${users.length}`);
        console.log(`Accounts: ${totalAccounts}`);
        console.log(`Transactions: ${totalTransactions}`);
        console.log(`Duration: ${duration}s`);
        console.log(`Default Password: ${CONFIG.DEFAULT_PASSWORD}`);
        console.log('='.repeat(50));

    } catch (error) {
        console.error(`\n Error during seeding:`, error);
        throw error;
    }
}

main()
  .catch((err) => {
    console.error('\n Fatal error:', err);
    process.exit(1);
  })
  .finally(async () => {
    console.log('\n Disconnecting from database.');
    await prisma.$disconnect();
    console.log('Disconnected');
  })