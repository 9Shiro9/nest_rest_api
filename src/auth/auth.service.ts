import { ForbiddenException, Injectable } from "@nestjs/common";
import { User } from "@prisma/client";
import { PrismaService } from "src/prisma/prisma.service";
import * as argon from "argon2";
import { AuthDto } from "./dto";
import { PrismaClientKnownRequestError } from "@prisma/client/runtime/library";
@Injectable({})
export class AuthService {
    constructor(private prisma : PrismaService){

    }
    async signup(dto : AuthDto){
        try {
            const hash = await argon.hash(dto.password)
            const user = await this.prisma.user.create({
            data : {
                email : dto.email ,
                hash
            } 
        })
        delete user.hash
        return user
        }
        catch(error) {
            if(error instanceof PrismaClientKnownRequestError){
                if(error.code === "P2002"){
                    throw new ForbiddenException("Credentials Taken")
                }
            }
            throw error;
        }
    }
    async signin(dto : AuthDto){
        //find the email
        const user = await this.prisma.user.findUnique({
            where : {
                email : dto.email,
            }
        })

        //throw error if not found
        if(!user){
            throw new ForbiddenException("Credentials incorrect")
        }

        //compare password
        const pwMatches = await argon.verify(user.hash , dto.password);
        
        //throw error if incorrect
        if(!pwMatches){
            throw new ForbiddenException("Credentials incorrect");
        }

        delete user.hash ;

        return user
    }
}