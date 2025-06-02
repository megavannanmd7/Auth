import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwt: JwtService) {}

  async signup(dto: SignupDto) {
    const hash = await bcrypt.hash(dto.password, 10);
    const user = await this.prisma.user.create({
      data: { username: dto.username, password: hash },
    });
    return user;
  }

  async login(dto: LoginDto, res: any) {
  const user = await this.prisma.user.findUnique({
    where: { username: dto.username },
  });
  if (!user || !(await bcrypt.compare(dto.password, user.password))) {
    throw new UnauthorizedException('Invalid credentials');
  }

  const accessToken = this.jwt.sign({ sub: user.id }, {
    secret: process.env.ACCESS_TOKEN_SECRET,
    expiresIn: '15m',
  });
  const refreshToken = this.jwt.sign({ sub: user.id }, {
    secret: process.env.REFRESH_TOKEN_SECRET,
    expiresIn: '7d',
  });

  await this.prisma.user.update({
    where: { id: user.id },
    data: { refreshToken },
  });

  res.cookie('accessToken', accessToken, {
    httpOnly: true,
    secure: false, // set to true in production (requires HTTPS)
    sameSite: 'lax',
  });
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: false,
    sameSite: 'lax',
  });

  // ✅ This is the important line to end the response
  res.status(200).json({ message: 'Logged in' });
}


  async refresh(userId: number, res: any) {
  const user = await this.prisma.user.findUnique({ where: { id: userId } });
  if (!user) throw new UnauthorizedException();

  const newAccessToken = this.jwt.sign({ sub: user.id }, {
    secret: process.env.ACCESS_TOKEN_SECRET,
    expiresIn: '15m',
  });
  const newRefreshToken = this.jwt.sign({ sub: user.id }, {
    secret: process.env.REFRESH_TOKEN_SECRET,
    expiresIn: '7d',
  });

  await this.prisma.user.update({
    where: { id: user.id },
    data: { refreshToken: newRefreshToken },
  });

  res.cookie('accessToken', newAccessToken, {
    httpOnly: true,
    secure: false, // for local testing
    sameSite: 'lax',
  });
  res.cookie('refreshToken', newRefreshToken, {
    httpOnly: true,
    secure: false,
    sameSite: 'lax',
  });

  // This line ends the response properly
  res.status(200).json({ message: 'Token refreshed' });
}


  async logout(userId: number, res: any) {
    await this.prisma.user.update({
      where: { id: userId },
      data: { refreshToken: null },
    });

    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');
    return { message: 'Logged out' };
  }

  async verifyRefreshToken(token: string): Promise<any> {
  try {
    return await this.jwt.verifyAsync(token, {
      secret: process.env.REFRESH_TOKEN_SECRET,
    });
  } catch {
    throw new UnauthorizedException('Invalid refresh token');
  }
}
}