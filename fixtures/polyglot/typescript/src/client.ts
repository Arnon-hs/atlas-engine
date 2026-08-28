import { exec as execute } from 'node:child_process';

export interface ClientOptions {
  name: string;
}

export class Client {
  constructor(private readonly options: ClientOptions) {}

  greet(): string {
    return `Hello, ${this.options.name}`;
  }
}

export const twice = (value: number): number => value * 2;

export function unsafeCommand(command: string): void {
  execute(command);
}
