-- AlterTable
ALTER TABLE "Account" ADD COLUMN     "AccountType" TEXT DEFAULT 'savings',
ADD COLUMN     "currency" TEXT DEFAULT 'NGN';
