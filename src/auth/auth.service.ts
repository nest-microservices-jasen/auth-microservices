import { HttpStatus, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';
import { LoginUserDto, RegisterUserDto } from './dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { type JwtPayloadCustom } from './interfaces/jwt.interface';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger('AuthService');
  constructor(private readonly jwtService: JwtService) {
    super();
  }
  onModuleInit() {
    this.$connect();
    this.logger.log('Connected to database MongoDB');
  }

  async signJwt(payload: JwtPayloadCustom) {
    return this.jwtService.sign(payload);
  }

  async register(registerUserDto: RegisterUserDto) {
    const { email, password, name } = registerUserDto;

    try {
      const userExists = await this.user.findUnique({
        where: {
          email,
        },
      });

      if (userExists) {
        throw new RpcException({
          status: 400,
          message: 'User already exists',
        });
      }
      const user = await this.user.create({
        data: {
          email,
          password: bcrypt.hashSync(password, 10),
          name,
        },
      });

      const { password: _, ...rest } = user;

      return {
        user: rest,
        token: await this.signJwt(rest),
      };
    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message,
      });
    }
  }

  async login(loginUserDto: LoginUserDto) {
    const { email, password } = loginUserDto;

    try {
      const userExists = await this.user.findUnique({
        where: {
          email,
        },
      });

      if (!userExists) {
        throw new RpcException({
          status: 400,
          message: 'Credenciales invalidas',
        });
      }

      const isPassword = bcrypt.compareSync(password, userExists.password);

      if (!isPassword) {
        throw new RpcException({
          status: HttpStatus.BAD_REQUEST,
          message: 'Credenciales invalidas',
        });
      }

      const { password: _, ...rest } = userExists;

      return {
        user: rest,
        token: await this.signJwt(rest),
      };
    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message,
      });
    }
  }

  async verifyToken(token: string) {
    try {
      const { sub, iat, exp, ...rest } = this.jwtService.verify(token, {
        secret: envs.jwtSecret,
      });

      return {
        user: rest,
        token: await this.signJwt(rest),
      };
    } catch (error) {
      console.log(error);
      throw new RpcException({
        status: 401,
        message: 'token invalido',
      });
    }
  }
}
