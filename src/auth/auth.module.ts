import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { MongooseModule } from '@nestjs/mongoose';
import { User, userSchema } from './schema/user.schema';
import {
  RefreshToken,
  RefreshTokenSchema,
} from './schema/refresh-token.schema';
import { ResetToken, ResetTokenSchema } from './schema/reset-token.schema';
import { MailService } from 'src/services/mail.services';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: User.name, schema: userSchema },
      { name: RefreshToken.name, schema: RefreshTokenSchema },
      { name: ResetToken.name, schema: ResetTokenSchema },
    ]),
  ],
  controllers: [AuthController],
  providers: [AuthService, MailService],
})
export class AuthModule {}
