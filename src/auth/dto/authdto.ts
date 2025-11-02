import { IsEmail, IsNotEmpty, IsOptional, IsPhoneNumber, IsString, IsUUID,  Length,  MinLength } from "class-validator";

export class UserLoginDto {
    @IsString()
    @IsNotEmpty()
    @IsEmail({}, {message:"Invalid email format"})
    email: string;

    @IsString()
    @MinLength(8, {message:"Password must be at least 8 characters."})
    password:string;

}

export class TwoFactorRequiredDto {
    @IsString()
    @IsNotEmpty()
    userId: string; // Temporary ID to pass to the /2fa/verify endpoint
    
    @IsString()
    @IsOptional()
    message?: string; // Optional message (e.g., "Two-factor authentication required.")
}

// --- 2FA DTO ---
export class TwoFactorVerifyDto {
    @IsString()
    @IsUUID('4', {message:'Invalid user ID'})
    userId: string;
    
    @IsString()
    @Length(6,6, {message: "OTP must be 6 digits"})
    otp: string;
}

// --- Token Pair DTO (Response) ---
export class TokenPairDto {
    @IsString()
    accessToken: string;

    @IsString()
    refreshToken: string
}
export class RefreshTokenDto {
    @IsString()
    refreshToken: string
}

export class RegisterDto {
    @IsString()
    @IsNotEmpty()
    @IsEmail({}, {message:"Invalid email format"})
    email: string;

    @IsString()
    @MinLength(8, {message:"Password must be at least 8 characters."})
    password:string;
   
    @IsString()
    firstName: string;

    @IsString()
    lastName: string;

    @IsString()
    middleName?: string;

    @IsString()
    phoneNumber: string;
}
export class UpdateDto {
    @IsOptional()
    @IsString()
    @IsNotEmpty()
    @IsEmail({}, {message:"Invalid email format"})
    email?: string;

    @IsOptional()
    @IsString()
    @MinLength(8, {message:"Password must be at least 8 characters."})
    password?:string;
   
    @IsOptional()
    @IsString()
    @MinLength(3)
    firstName?: string;

    @IsOptional()
    @IsString()
    @MinLength(3)
    lastName?: string;

    @IsOptional()
    @IsString()
    @MinLength(3)
    middleName?: string;
    
    @IsOptional()
    @IsString()
    @IsPhoneNumber()
    phoneNumber?: string;
}