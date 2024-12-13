import { config } from 'dotenv';
config();
import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
const mongo_uri = process.env.MONGO_URI!;

@Module({
  imports: [
    MongooseModule.forRootAsync({
      useFactory: () => ({
        uri: mongo_uri,
        useNewUrlParser: true,
        useUnifiedTopology: true,
      }),
    }),
  ],
})
export class DatabaseModule {}
