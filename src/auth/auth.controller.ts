import { Controller, Post, Body, Res, Req, UseGuards, Get } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  signup(@Body() dto: SignupDto) {
    return this.authService.signup(dto);
  }

  @Post('login')
  login(@Body() dto: LoginDto, @Res() res) {
    return this.authService.login(dto, res);
  }

  @UseGuards(JwtAuthGuard)
  @Get('protected')
  getProtected(@Req() req) {
    return { userId: req.user.userId, message: 'Access granted' };
  }

  @Post('refresh')
async refresh(@Req() req, @Res() res) {
  console.log('Cookies:', req.cookies);
  const refreshToken = req.cookies?.refreshToken;
  if (!refreshToken) {
    return res.status(401).json({ message: 'No refresh token provided' });
  }
  try {
    const payload = await this.authService.verifyRefreshToken(refreshToken);
    return this.authService.refresh(payload.sub, res);
  } catch (error) {
    return res.status(401).json({ message: 'Invalid refresh token' });
  }
}


  @Post('logout')
  logout(@Req() req, @Res() res) {
    return this.authService.logout(req.user?.userId, res);
  }
}
