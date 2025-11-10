import {
  IsDecimal,
  IsNotEmpty,
  IsOptional,
  IsString,
  IsUUID,
} from 'class-validator';

export class TransactionsDto {
  @IsString()
  @IsNotEmpty()
  destinationAccountNumber: string;

  @IsDecimal()
  @IsNotEmpty()
  amount: number;

  @IsString()
  @IsOptional()
  narration?: string;

  @IsString()
  @IsOptional()
  reference?: string;

  @IsString()
  @IsOptional()
  sourceAccountNumber?: string;
}
