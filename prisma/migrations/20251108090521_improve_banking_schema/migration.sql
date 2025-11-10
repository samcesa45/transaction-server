/*
  Warnings:

  - The `accountType` column on the `Account` table would be dropped and recreated. This will lead to data loss if there is data in the column.
  - You are about to drop the column `remark` on the `Transaction` table. All the data in the column will be lost.
  - The `status` column on the `Transaction` table would be dropped and recreated. This will lead to data loss if there is data in the column.
  - A unique constraint covering the columns `[phoneNumber]` on the table `User` will be added. If there are existing duplicate values, this will fail.
  - A unique constraint covering the columns `[bvn]` on the table `User` will be added. If there are existing duplicate values, this will fail.
  - Made the column `userId` on table `Account` required. This step will fail if there are existing NULL values in that column.
  - Made the column `currency` on table `Account` required. This step will fail if there are existing NULL values in that column.

*/
-- CreateEnum
CREATE TYPE "AccountType" AS ENUM ('savings', 'current', 'fixed_deposit');

-- CreateEnum
CREATE TYPE "TransactionStatus" AS ENUM ('pending', 'successful', 'failed', 'reversed');

-- CreateEnum
CREATE TYPE "TransactionType" AS ENUM ('transfer', 'airtime', 'bills', 'withdrawal', 'deposit');

-- DropForeignKey
ALTER TABLE "public"."Account" DROP CONSTRAINT "Account_userId_fkey";

-- AlterTable
ALTER TABLE "Account" ADD COLUMN     "dailyLimit" DECIMAL(10,2),
ADD COLUMN     "isActive" BOOLEAN NOT NULL DEFAULT true,
ADD COLUMN     "isPrimary" BOOLEAN NOT NULL DEFAULT false,
ALTER COLUMN "userId" SET NOT NULL,
ALTER COLUMN "currency" SET NOT NULL,
DROP COLUMN "accountType",
ADD COLUMN     "accountType" "AccountType" NOT NULL DEFAULT 'savings';

-- AlterTable
ALTER TABLE "Transaction" DROP COLUMN "remark",
ADD COLUMN     "balanceAfter" DECIMAL(10,2),
ADD COLUMN     "balanceBefore" DECIMAL(10,2),
ADD COLUMN     "failureReason" TEXT,
ADD COLUMN     "narration" TEXT,
ADD COLUMN     "reference" TEXT DEFAULT 'INTERBANK_TRANSFER',
ADD COLUMN     "transactionType" "TransactionType" NOT NULL DEFAULT 'transfer',
DROP COLUMN "status",
ADD COLUMN     "status" "TransactionStatus" NOT NULL DEFAULT 'pending';

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "bvn" TEXT,
ADD COLUMN     "dateOfBirth" TIMESTAMP(3);

-- CreateIndex
CREATE INDEX "Account_accountNumber_idx" ON "Account"("accountNumber");

-- CreateIndex
CREATE INDEX "Account_userId_isPrimary_idx" ON "Account"("userId", "isPrimary");

-- CreateIndex
CREATE INDEX "Transaction_sourceAccountId_createdAt_idx" ON "Transaction"("sourceAccountId", "createdAt");

-- CreateIndex
CREATE INDEX "Transaction_status_createdAt_idx" ON "Transaction"("status", "createdAt");

-- CreateIndex
CREATE INDEX "Transaction_createdAt_idx" ON "Transaction"("createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "User_phoneNumber_key" ON "User"("phoneNumber");

-- CreateIndex
CREATE UNIQUE INDEX "User_bvn_key" ON "User"("bvn");

-- CreateIndex
CREATE INDEX "User_email_idx" ON "User"("email");

-- CreateIndex
CREATE INDEX "User_phoneNumber_idx" ON "User"("phoneNumber");

-- AddForeignKey
ALTER TABLE "Account" ADD CONSTRAINT "Account_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
