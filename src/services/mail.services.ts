import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';
import * as AWS from 'aws-sdk';

@Injectable()
export class MailService {
  private transporter: nodemailer.Transporter;

  constructor() {
    // Configure AWS SDK
    AWS.config.update({
      accessKeyId: process.env.AWS_ACCESS_KEY_ID,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
      region: process.env.AWS_REGION,
    });

    // Configure Nodemailer to use AWS SES
    this.transporter = nodemailer.createTransport({
      SES: new AWS.SES({ apiVersion: '2010-12-01' }),
    });
  }

  async sendPasswordResetEmail(to: string, token: string) {
    const resetLink = `${process.env.BASE_URL}/reset-password?token=${token}`;
    const mailOptions = {
      from: 'Auth Service <gadarsh747@gmail.com>', // Replace with your verified SES email address
      to,
      subject: 'Password Reset Request',
      html: `
        <p>You requested a password reset. Click the link below to reset your password:</p>
        <p><a href="${resetLink}">Reset Password</a></p>
      `,
    };

    await this.transporter.sendMail(mailOptions);
  }

  async sendConfirmationEmail(to: string, token: string) {
    const confirmationLink = `${process.env.BASE_URL}/confirm-email?token=${token}`;
    const mailOptions = {
      from: 'Auth Service <gadarsh747@gmail.com>', // Replace with your verified SES email address
      to,
      subject: 'Email Confirmation',
      html: `
        <p>Thank you for registering, ${to}!</p>
        <p>Please confirm your email by clicking the link below:</p>
        <a href="${confirmationLink}">Confirm Email</a>
      `,
    };

    await this.transporter.sendMail(mailOptions);
  }
}
