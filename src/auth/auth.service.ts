import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { JwtService } from '@nestjs/jwt';
import { Model } from 'mongoose';

import * as bcryptjs from 'bcryptjs';

import { CreateUserDto, UpdateAuthDto, LoginDto, RegisterUserDto  } from './dto';

import { User } from './entities/user.entity';

import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-respopmse';

@Injectable()
export class AuthService {


  constructor(
    @InjectModel( User.name ) 
    private userModel: Model<User>,

    private jwtService: JwtService,
  ) {}


  async create(createUserDto: CreateUserDto): Promise<User> {
   
    try {
      
      // 1.- Encriptar contraseña
      const { password, ...UserDta } = createUserDto;      
      
      const newUser = new this.userModel({
        password: bcryptjs.hashSync( password, 10 ),
        ...UserDta
      });


      // 2.- Guardar Usuario
      await newUser.save();


      // 3.- Retornar el usuario sin la Contraseña 
      const { password:_, ...user } = newUser.toJSON();

      return user;

    } catch (error) {
      if ( error.code === 11000 ) {
        throw new BadRequestException(`${ createUserDto.email } ya existe`)
      }
      throw new InternalServerErrorException('Alguna cosa terrible puede suceder!!!!');
    }

   }


   async register( registerDto: RegisterUserDto ): Promise<LoginResponse> {

    const user = await this.create( registerDto );

    return {
      user: user,
      token: this.getToken( { id: user._id } )
    }

   }



  async login( loginDto: LoginDto): Promise<LoginResponse> {

    const { email, password } = loginDto;

    const user = await this.userModel.findOne({ email });

    if (!user) {
      throw new UnauthorizedException('Credenciales no válidas - email !!!');
    }

    if (!bcryptjs.compareSync( password, user.password) ) {
      throw new UnauthorizedException('Credenciales no válidas - password !!!');
    }

    const { password:_ , ...rest } = user.toJSON();
    return {
      user: rest,
      token: this.getToken( { id: user.id } ),
    }

  }  
  
  
  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  async findUserById( id: string ){
    const user = await this.userModel.findById( id );
    const { password, ...rest } = user.toJSON();
    return rest;
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

  getToken( payload: JwtPayload ) {

    const token = this.jwtService.sign(payload);
    return token; 

  }
}
