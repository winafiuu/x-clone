import { Lucia, Session, User } from "lucia";
import prisma from "./lib/prisma";
import { PrismaAdapter } from "@lucia-auth/adapter-prisma";
import { cache } from "react";
import { cookies } from "next/headers";

const adapter = new PrismaAdapter(prisma.session, prisma.user);

export const lucia = new Lucia(adapter, {
  sessionCookie: {
    // this sets cookies with super long expiration
    // since Next.js doesn't allow Lucia to extend cookie expiration when rendering pages
    expires: false,
    attributes: {
      // set to `true` when using HTTPS
      secure: process.env.NODE_ENV === "production",
    },
  },

  getUserAttributes: (attributes) => {
    return {
      id: attributes.id,
      username: attributes.username,
      displayName: attributes.displayName,
      email: attributes.email,
      googleId: attributes.googleId,
      avatarUrl: attributes.avatarUrl,
      bio: attributes.bio,
      location: attributes.location,
      website: attributes.website,
      birthData: attributes.birthData,
    };
  },
});

declare module "lucia" {
  interface Register {
    Lucia: typeof lucia;
    DatabaseUserAttributes: DatabaseUserAttributes;
  }
}

interface DatabaseUserAttributes {
  id: string;
  username: string;
  displayName: string | null;
  email: string | null;
  googleId: string | null;
  avatarUrl: string | null;
  bio: string | null;
  location: string | null;
  website: string | null;
  birthData: string | null;
}

export const getUser = cache(
  async (): Promise<
    { user: User; session: Session } | { user: null; session: null }
  > => {
    const sessionId = cookies().get(lucia.sessionCookieName)?.value ?? null;

    if (!sessionId) return { user: null, session: null };

    const result = await lucia.validateSession(sessionId);

    try {
      if (result.session && result.session.fresh) {
        const sessionCookie = lucia.createSessionCookie(result.session.id);
        cookies().set(
          sessionCookie.name,
          sessionCookie.value,
          sessionCookie.attributes,
        );
      }

      if (!result.session) {
        const sessionCookie = lucia.createBlankSessionCookie();
        cookies().set(
          sessionCookie.name,
          sessionCookie.value,
          sessionCookie.attributes,
        );
      }
    } catch {
      // Next.js throws error when attempting to set cookies when rendering page
    }

    return result;
  },
);
