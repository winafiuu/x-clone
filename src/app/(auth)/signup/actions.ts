"use server";

import prisma from "@/lib/prisma";
import { SignupValues, signupSchema } from "@/lib/validation";
import { hash } from "@node-rs/argon2";
import { generateIdFromEntropySize } from "lucia";
import { lucia } from "@/auth";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";

export async function signUp(formData: SignupValues) {
  let cookiesSet = false;

  try {
    const { email, username, password } = signupSchema.parse(formData);

    const passwordHash = await hash(password, {
      memoryCost: 19456,
      timeCost: 2,
      outputLen: 32,
      parallelism: 1,
    });

    const userId = generateIdFromEntropySize(10); // 16 characters long

    const existingUsername = await prisma.user.findFirst({
      where: {
        username: {
          equals: username,
          mode: "insensitive",
        },
      },
    });
    if (existingUsername) {
      return {
        error: "Username alreay taken!",
      };
    }

    const existingEmail = await prisma.user.findFirst({
      where: {
        email: {
          equals: email,
          mode: "insensitive",
        },
      },
    });
    if (existingEmail) {
      return {
        error: "Email alreay exists!",
      };
    }

    await prisma.user.create({
      data: {
        id: userId,
        username,
        email: email,
        passwordHash,
        displayName: username.split("@")[0],
      },
    });

    const session = await lucia.createSession(userId, {});
    const sessionCookie = lucia.createSessionCookie(session.id);
    cookies().set(
      sessionCookie.name,
      sessionCookie.value,
      sessionCookie.attributes,
    );

    cookiesSet = true;
  } catch (err) {
    console.log(err);
    return {
      error: "Something went wrong!",
    };
  }

  // can't put redirect in the try catch block because redirect returns error internally. check next docs
  if (cookiesSet) {
    return redirect("/");
  }
}
