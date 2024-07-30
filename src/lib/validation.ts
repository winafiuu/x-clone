import { z } from "zod";

const zodRequired = z.string().trim().min(1, "Required");

export const signupSchema = z.object({
  email: zodRequired.email("Invalid email"),
  username: zodRequired.regex(
    /^[a-zA-Z0-9-_]+$/,
    "Allowed characters: Numbers, Letters, - and _",
  ),
  password: zodRequired.min(8, "Must be at least 8 characters"),
});
export type SignupValues = z.infer<typeof signupSchema>;

export const signinSchema = z.object({
  username: zodRequired,
  password: zodRequired,
});
export type SigninValues = z.infer<typeof signinSchema>;
