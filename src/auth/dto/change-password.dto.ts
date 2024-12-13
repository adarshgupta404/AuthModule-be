import { IsString } from 'class-validator';

export class ChangePasswordDto {
  @IsString()
  oldpassword: string;
  @IsString()
  newpassword: string;
}
