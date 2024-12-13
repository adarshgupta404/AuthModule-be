import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { Observable } from 'rxjs';
interface CustomRequest extends Request {
  payload?: any;
}
@Injectable()
export class AuthGaurd implements CanActivate {
  constructor(private jwtService: JwtService) {}
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const request: CustomRequest = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);
    if (!token) {
      throw new UnauthorizedException('Invalid Token');
    }
    try {
      const payload = this.jwtService.verify(token);
      request.payload = payload;
    } catch (error) {
      Logger.error(error.message);
      throw new UnauthorizedException('Invalid Token');
    }
    return true;
  }
  private extractTokenFromHeader(request: Request): string | undefined {
    return request.headers.authorization?.split(' ')[1];
  }
}
