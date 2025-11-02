import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { Redis } from 'ioredis';

@Injectable()
export class RedisService implements OnModuleInit, OnModuleDestroy {
    private client: Redis;

    async onModuleInit() {
        this.client = new Redis({
            host:process.env.REDIS_HOST || 'localhost',
            port: parseInt(process.env.REDIS_PORT || '6379'),
            password:process.env.REDIS_PASSWORD,
            db: parseInt(process.env.REDIS_DB || '0'),
            retryStrategy: (times) => {
                const delay = Math.min(times * 50, 2000);
                return delay;
            }
        });

        this.client.on('error', (err) => {
            console.error('Redis Client Error', err);
        });

        this.client.on('connect', () => {
            console.log('Redis Client Connected')
        });
        
    }

    async onModuleDestroy() {
        await this.client.quit();
    }

    async get(key: string): Promise<string | null> {
        return this.client.get(key);
    }

    async set(key:string,value:string):Promise<'OK' | null>{
        return this.client.set(key,value);
    }

    async setWithExpiry(key:string,value:string,seconds:number):Promise<"OK" | null>{
        return this.client.set(key,value, 'EX', seconds)
    }
    async setWithExpiryMs(key:string,value:string,milliseconds:number):Promise<"OK" | null>{
        return this.client.set(key,value, 'PX', milliseconds)
    }
    async setex(key:string,seconds:number,value:string):Promise<"OK">{
        return this.client.setex(key,seconds,value)
    }
    async del(key:string):Promise<number> {
        return this.client.del(key);
    }
    async exists(key: string): Promise<number> {
        return this.client.exists(key);
    }

    async expire(key: string, seconds: number): Promise<number> {
        return this.client.expire(key,seconds);
    }
    async ttl(key:string): Promise<number> {
        return this.client.ttl(key);
    }

    //Pattern-based deletion (Use with caution)
    async deletePattern(pattern: string): Promise<number> {
        const keys = await this.client.keys(pattern);
        if(keys.length === 0) return 0;
        return this.client.del(...keys);
    }
}
