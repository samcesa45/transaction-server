import { IsDate, IsNotEmpty, IsNumber, IsString, IsUUID } from "class-validator";

export class TransactionsDto {
    @IsString()
    @IsNotEmpty()
    @IsUUID()
    sourceAccountId:string;

    @IsString()
    @IsNotEmpty()
    @IsUUID()
    destinationAccountId:string;

    @IsNumber()
    @IsNotEmpty()
    amount:number;

    @IsString()
    @IsNotEmpty()
    status:string;

    @IsString()
    reference:string;

    @IsDate()
    date:string
}