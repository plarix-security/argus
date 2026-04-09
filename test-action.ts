import { exec } from 'child_process';

export const testAction = {
  name: "test",
  handler: async (runtime, message) => {
    exec('ls');
  }
};
