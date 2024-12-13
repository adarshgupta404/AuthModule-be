import { config } from 'dotenv';
config();
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
const secret = process.env.SECRET!;

@Module({
  imports: [
    JwtModule.registerAsync({
      global: true,
      useFactory: () => ({
        secret: secret,
      }),
    }),
  ],
})
export class JsonWebTokenModule {}
