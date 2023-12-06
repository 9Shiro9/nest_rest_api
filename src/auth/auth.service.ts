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
    signin(){
        return {msg : "I have signed in"}
    }
}