import { IsString } from 'class-validator';

export class BiometricDto {
  @IsString()
  deviceId: string;

  @IsString()
  challenge: string; //challenge received from server

  @IsString()
  signature: string; //signature of challenge signed by device
}
