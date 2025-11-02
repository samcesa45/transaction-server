-- AlterTable
ALTER TABLE "User" ADD COLUMN     "lastLoginAttempt" TIMESTAMP(3),
ADD COLUMN     "lastLogout" TIMESTAMP(3);
