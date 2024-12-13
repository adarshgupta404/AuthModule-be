import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  Req,
  Logger,
  UseGuards,
  Put,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateAuthDto } from './dto/create-auth.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refreshToken.dto';
import { AuthGaurd } from './guards/auth.guard';
import { ChangePasswordDto } from './dto/change-password.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { resetPasswordDto } from './dto/reset-password.dto';

@Controller('api/auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  create(@Body() registerDto: RegisterDto) {
    return this.authService.create(registerDto);
  }

  @Post('confirm-email')
  async confirmEmail(@Body('token') token: string) {
    return this.authService.confirmEmail(token);
  }

  @Post('login')
  login(@Body() credentials: LoginDto) {
    return this.authService.login(credentials);
  }

  @Post('register-google-facebook')
  registerGoogleFacebook(
    @Body()
    data: {
      name: string;
      email: string;
      picture: string;
      sub: string;
      type:string
    },
  ) {
    return this.authService.registerWithGoogleFacebook(data);
  }

  @Post('refresh')
  refreshToken(@Body() refreshTokenDto: RefreshTokenDto) {
    return this.authService.refreshToken(refreshTokenDto.token);
  }

  @Get()
  @UseGuards(AuthGaurd)
  findAll(@Req() req: any) {
    return { message: 'accessed', payload: req.payload };
    // return this.authService.findAll();
  }

  @Put('change-password')
  @UseGuards(AuthGaurd)
  changePassword(
    @Req() req: any,
    @Body() changePasswordDto: ChangePasswordDto,
  ) {
    return this.authService.changePassword(
      req.payload.userId,
      changePasswordDto.oldpassword,
      changePasswordDto.newpassword,
    );
  }

  @Post('forgot-password')
  forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto) {
    return this.authService.forgotPassword(forgotPasswordDto.email);
  }

  @Put('reset-password')
  async resetPassword(@Body() resetPasswordDto: resetPasswordDto) {
    return this.authService.resetPassword(
      resetPasswordDto.newpassword,
      resetPasswordDto.resetToken,
    );
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateAuthDto: UpdateAuthDto) {
    return this.authService.update(+id, updateAuthDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.authService.remove(+id);
  }
}
