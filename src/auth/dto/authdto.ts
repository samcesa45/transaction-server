import { Type } from 'class-transformer';
import {
  IsDate,
  IsDateString,
  IsEmail,
  IsNotEmpty,
  IsOptional,
  IsString,
  IsUUID,
  Length,
  Matches,
  MinLength,
} from 'class-validator';

export class UserLoginDto {
  @IsString()
  @IsNotEmpty()
  @IsEmail({}, { message: 'Invalid email format' })
  email: string;

  @IsString()
  @MinLength(8, { message: 'Password must be at least 8 characters.' })
  password: string;

  @IsString()
  deviceId: string;

  @IsString()
  @IsOptional()
  deviceName?: string;

  @IsString()
  @IsOptional()
  fcmToken?: string;
}

export class BiometricLoginDto {
  @IsString()
  deviceId: string;

  @IsString()
  challenge: string; //challenge received from server

  @IsString()
  signature: string; //signature of challenge signed by device
}

export class SetTransactionPinDto {
  @IsString()
  @Length(4, 6)
  @Matches(/^\d+$/, { message: 'Pin must contain only numbers' })
  transactionPin: string;

  @IsString()
  @Length(4, 6)
  confirmPin: string;
}

export class VerifyTransactionPinDto {
  @IsString()
  @Length(4, 6)
  transactionPin: string;
}

export class VerifyOTPDto {
  @IsString()
  userId: string;

  @IsString()
  @Length(6, 6)
  otp: string;

  @IsString()
  purpose: 'email_verification' | 'phone_verification' | 'password_reset';
}

export class EnableBioMetricDto {
  @IsString()
  deviceId: string;

  @IsString()
  biometricPublicKey: string;
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
  @IsUUID('4', { message: 'Invalid user ID' })
  userId: string;

  @IsString()
  @Length(6, 6, { message: 'OTP must be 6 digits' })
  otp: string;
}

// --- Token Pair DTO (Response) ---
export class TokenPairDto {
  @IsString()
  accessToken: string;

  @IsString()
  refreshToken: string;
}
export class RefreshTokenDto {
  @IsString()
  refreshToken: string;
}

export class RegisterDto {
  @IsString()
  @IsNotEmpty()
  @IsEmail({}, { message: 'Invalid email format' })
  email: string;

  @IsString()
  @MinLength(8, { message: 'Password must be at least 8 characters.' })
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, {
    message:
      'Password must contain uppercase, lowercase, number and special characters',
  })
  password: string;

  @IsString()
  @MinLength(3)
  firstName: string;

  @IsString()
  @MinLength(3)
  lastName: string;

  @IsString()
  @IsOptional()
  middleName?: string;
  
  @Type(() => Date)
  @IsDate({ message: 'Invalid date format. Use YYYY-MM-DD or ISO-8601 string' })
  dateOfBirth: string;

  @IsString()
  @Matches(/^\+?[0-9]\d{1,14}$/, { message: 'Phone number must be in international format (e.g. +2348012345678)' })
  phoneNumber: string;

  @IsString()
  deviceId: string;

  @IsString()
  @IsOptional()
  deviceName?: string;
}
