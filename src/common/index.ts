export interface RequestWithUser extends Request {
  user: { userId: string; email: string };
}
