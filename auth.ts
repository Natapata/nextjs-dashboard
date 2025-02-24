import NextAuth from 'next-auth';
import { authConfig } from './auth.config';
import Credentials from 'next-auth/providers/credentials';
import { z } from 'zod';
import type { User } from '@/app/lib/definitions';
import bcrypt from 'bcrypt';
import postgres from 'postgres';
import pgPromise from 'pg-promise';

//const sql = postgres(process.env.POSTGRES_URL!, {ssl: 'require'} );

const pgp = pgPromise();
const db = pgp(process.env.POSTGRES_URL!, {ssl: 'require'});
 
// async function getUser(email: string): Promise<User | undefined> {
//     try{
//         const user = await sql<User[]>`SELECT * FROM users WHERE email = ${email}`;
//         return user[0];
//     }catch(error){
//         console.error('Database Error:', error);
//         throw new Error('Failed to fetch user.');
//     }
// }

async function getUserWithBind(email: string): Promise<User | undefined> {
  try {
    const user = await db.oneOrNone<User>(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );
    return user || undefined;
  } catch (error) {
    console.error('Database Error:', error);
    throw new Error('Failed to fetch user.');
  }
}

export const { auth, signIn, signOut } = NextAuth({
    ...authConfig,
    providers: [
      Credentials({
        async authorize(credentials) {
            const parsedCredentials = z
            .object({ email: z.string().email(), password: z.string().min(6) })
            .safeParse(credentials);
            
            if (parsedCredentials.success) {
                const { email, password } = parsedCredentials.data;
                const user = await getUserWithBind(email);
                if (!user) return null;
                const passwordsMatch = await bcrypt.compare(password, user.password);
                if (passwordsMatch) return user;
              }
       
              console.log('Invalid email or password.');
              return null;
            },
          }),
        ],
      });