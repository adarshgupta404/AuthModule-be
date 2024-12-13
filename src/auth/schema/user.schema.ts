import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema({ timestamps: true })
export class User extends Document {
  @Prop({ required: true })
  name: string;

  @Prop({ required: true })
  email: string;

  @Prop({ default: '' })
  image?: string;

  @Prop({ default: '' })
  namespace?: string;

  @Prop({ default: '' })
  googleId?: string;

  @Prop({ default: '' })
  facebookId?: string;

  @Prop({ required: true })
  password: string;

  @Prop({ default: false })
  isConfirmed: boolean;

  @Prop({ default: null })
  confirmationToken: string;
}

export const userSchema = SchemaFactory.createForClass(User);
