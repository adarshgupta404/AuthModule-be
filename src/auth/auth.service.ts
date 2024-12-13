import {
  BadRequestException,
  ConflictException,
  Injectable,
  InternalServerErrorException,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import * as bcrypt from 'bcrypt';
import mongoose, { Model, Types } from 'mongoose';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { v4 as uuid } from 'uuid';
import { User } from './schema/user.schema';
import { RefreshToken } from './schema/refresh-token.schema';
import { nanoid } from 'nanoid';
import { ResetToken } from './schema/reset-token.schema';
import { MailService } from 'src/services/mail.services';
@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<User>,
    @InjectModel(RefreshToken.name)
    private readonly refreshTokenModel: Model<RefreshToken>,
    @InjectModel(ResetToken.name)
    private readonly resetTokenModel: Model<ResetToken>,
    private jwtService: JwtService,
    private mailService: MailService,
  ) {}

  async create(registerDto: RegisterDto) {
    const { email, name, password } = registerDto;

    const emailInUse = await this.userModel.findOne({ email });
    if (emailInUse && emailInUse.isConfirmed) {
      throw new ConflictException('Email already in use!');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const confirmationToken = this.jwtService.sign(
      { email },
      { expiresIn: '1h' },
    );

    if (emailInUse && !emailInUse.isConfirmed) {
      emailInUse.password = hashedPassword;
      const confirmationToken = this.jwtService.sign(
        { email },
        { expiresIn: '1h' },
      );
      emailInUse.confirmationToken = confirmationToken;
      await emailInUse.save();
    } else {
      const newUser = await this.userModel.create({
        name,
        email,
        password: hashedPassword,
        isConfirmed: false,
        confirmationToken,
      });
    }

    await this.mailService.sendConfirmationEmail(email, confirmationToken);

    return {
      message:
        'Registration successful. Please confirm your email to activate your account.',
      user: { name, email },
    };
  }

  async registerWithGoogleFacebook(data: {
    name: string;
    email: string;
    picture: string;
    sub: string;
    type: string;
  }) {
    const { name, email, picture, sub, type } = data;
    let user = await this.userModel.findOne({ email });

    if (user) {
      if (type === 'google') {
        user.googleId = sub;
        user.image = picture;
        await user.save();
      }
      if (type === 'facebook') {
        user.facebookId = sub;
        user.image = picture;
        await user.save();
      }

      // Return a token for the existing user
      return this.generateUserToken({
        userId: user._id,
        name: user.name,
        email: user.email,
        image: user.image,
        namespace: user.namespace,
      });
    }
    const password = nanoid(10);
    const hashedPassword = await bcrypt.hash(password, 10);
    // If user doesn't exist, create a new one
    user = await this.userModel.create({
      name,
      email,
      image: picture,
      googleId: type === 'google' ? sub : '',
      facebookId: type === 'facebook' ? sub : '',
      password: hashedPassword,
      isConfirmed: true,
      confirmationToken: null,
    });

    return await this.generateUserToken({
      userId: user._id,
      name: user.name,
      email: user.email,
      image: user.image,
      namespace: user.namespace,
    });
  }

  async confirmEmail(token: string) {
    try {
      // Verify token
      const payload = this.jwtService.verify(token);
      const { email } = payload;

      const user = await this.userModel.findOne({ email });
      if (!user) {
        throw new NotFoundException('User not found');
      }

      if (user.isConfirmed) {
        throw new BadRequestException('Email already confirmed');
      }

      user.isConfirmed = true;
      user.confirmationToken = null;
      await user.save();

      return { message: 'Email confirmed successfully!', status: 'success' };
    } catch (error) {
      throw new UnauthorizedException('Invalid or expired token');
    }
  }

  async login(credentials: LoginDto) {
    const { email, password } = credentials;
    const user = await this.userModel.findOne({ email, isConfirmed: true });
    if (!user) {
      throw new UnauthorizedException('User not found!');
    }
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      throw new UnauthorizedException('Wrong Credentials!');
    }
    const access_token = await this.generateUserToken({
      userId: user._id,
      name: user.name,
      email: user.email,
      image: user.image,
      namespace: user.namespace,
    });
    return access_token;
  }

  async generateUserToken(user: {
    userId: any;
    name: string;
    email: string;
    image: string;
    namespace: string;
  }) {
    const access_token = this.jwtService.sign(user, { expiresIn: '1d' });
    const refresh_token = uuid();
    await this.storeRefreshToken(refresh_token, user.userId);
    return { access_token, refresh_token };
  }

  async storeRefreshToken(token: string, userId: any) {
    const expireDate = new Date();
    expireDate.setDate(expireDate.getDate() + 3);
    const existingToken = await this.refreshTokenModel.findOne({
      userId,
      expireDate: { $gt: new Date() },
    });

    if (existingToken) {
      console.log('exists');
      await this.refreshTokenModel.updateOne(
        { userId },
        { $set: { token, expireDate } },
        { upsert: true },
      );
    } else {
      console.log('not exists');
      await this.refreshTokenModel.create({
        token,
        userId,
        expireDate,
      });
    }
  }

  async refreshToken(refreshToken: string) {
    const token = await this.refreshTokenModel.findOne({
      token: refreshToken,
      expireDate: {
        $gte: new Date(),
      },
    });
    if (!token) {
      throw new UnauthorizedException();
    }
    const user = await this.userModel
      .findOne({ _id: token.userId })
      .select('-password');
    if (!user) {
      throw new UnauthorizedException('User not found!');
    }
    const userDetails = {
      userId: user._id,
      name: user.name,
      email: user.email,
      image: user.image,
      namespace: user.namespace,
    };
    return this.generateUserToken(userDetails);
  }
  async changePassword(
    userId: string,
    oldpassword: string,
    newpassword: string,
  ) {
    const user = await this.userModel.findOne({ _id: userId });
    if (!user) {
      throw new NotFoundException('User Not Found!');
    }
    const passwordMatch = await bcrypt.compare(oldpassword, user.password);
    if (!passwordMatch) {
      throw new UnauthorizedException('Wrong Credentials!');
    }
    if (passwordMatch) {
      const newHashedPassword = await bcrypt.hash(newpassword, 10);
      user.password = newHashedPassword;
      await user.save();
      return { message: 'Password changed successfully!' };
    }
  }

  async forgotPassword(email: string) {
    const user = this.userModel.findOne({ email });
    if (user) {
      const resetToken = nanoid(64);
      const expireDate = new Date();
      expireDate.setDate(expireDate.getDate() + 1);
      await this.resetTokenModel.create({
        token: resetToken,
        userId: (await user)._id,
        expireDate,
      });
      this.mailService.sendPasswordResetEmail(email, resetToken);
    }
    return { message: 'If user exists, this will recieve an email!' };
  }

  async resetPassword(newpassword: string, resetToken: string) {
    const token = await this.resetTokenModel.findOne({
      token: resetToken,
      expireDate: { $gte: new Date() },
    });

    if (!token) {
      throw new UnauthorizedException('Invalid Link!');
    }

    const user = await this.userModel.findById(token.userId);
    // Logger.log(user);
    if (!user) {
      throw new InternalServerErrorException();
    }

    user.password = await bcrypt.hash(newpassword, 10);
    await user.save();
    return { status: 'success', message: 'Reset password Successful!' };
  }

  findAll() {
    return `This action returns all auth`;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }
}
