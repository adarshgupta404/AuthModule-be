import { IsString, Matches, MinLength } from 'class-validator';

export class resetPasswordDto {
  @IsString()
  resetToken: string;

  @IsString()
  @MinLength(6)
  @Matches(/^(?=.*[0-9])/, {
    message: 'Password must contain atleast one number.',
  })
  newpassword: string;
}
