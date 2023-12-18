import { Injectable } from '@nestjs/common';

import { spawn } from 'child_process';

@Injectable()
export class AppService {
  getHello(): string {
    return 'Hello Safe Net Sentry!';
  }

  scanNetwork(): any {
    try {
      // Call the Python script for scanning
      const scanScript = spawn('python3', ['src/script/detector.py']);

      scanScript.stdout.on('data', async (data) => {
        const scanResult = JSON.parse(data.toString());
        console.log(scanResult);
        return scanResult;
      });

      scanScript.stderr.on('data', (err) => {
        console.error(`Error in Python script: ${err}`);
        return err;
      });
    } catch (err) {}
  }
}
