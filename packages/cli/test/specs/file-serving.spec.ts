import { test } from '@oclif/test';
import axios from 'axios';
import { expect } from 'chai';
import { readFileSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, resolve } from 'path';

const relativeError =
  'Access to relative path outside of the allowed base directory';
const absoluteError =
  'Access to absolute path outside of the original static base directory';
const rootError = 'Templated file path requires a non-root base directory';

// environment generated at runtime as absolute paths are OS dependent
const absoluteEnvPath = join(tmpdir(), 'mockoon-cli-file-serving.json');

/**
 * Get the raw response body (prevent axios from parsing JSON bodies)
 *
 * @param port
 * @param path
 */
const getBody = async (port: number, path: string): Promise<string> => {
  const response = await axios.get(`http://localhost:${port}${path}`, {
    transformResponse: [(data) => data]
  });

  return response.data;
};

describe('File serving', () => {
  test
    .stdout()
    .command([
      'start',
      '--data',
      './test/data/envs/file.json',
      '--disable-log-to-file'
    ])
    .do(async () => {
      let body: string;

      // path traversal is authorized when the path is not templated
      body = await getBody(3000, '/file');
      expect(body).to.contain('filecontent');

      // templated relative path inside the environment directory
      body = await getBody(3000, '/param1/mock1.json');
      expect(body).to.contain('"name": "mock1"');

      // templated relative paths escaping the environment directory
      body = await getBody(3000, '/param1/..%2Fbody-files%2Ffile1.txt');
      expect(body).to.contain(relativeError);
      expect(body).to.not.contain('filecontent');

      // templated relative path staying within its static base directory
      body = await getBody(3000, '/param2/file1');
      expect(body).to.contain('filecontent');

      // templated relative path escaping its static base directory
      body = await getBody(3000, '/param2/..%2Fenvs%2Fmock1');
      expect(body).to.contain(relativeError);

      // partially templated file name (helper in the middle of the file name)
      body = await getBody(3000, '/testfile/1');
      expect(body).to.contain('filecontent');

      body = await getBody(3000, '/testfile/2');
      expect(body).to.contain('filecontent2');

      body = await getBody(3000, '/testfile/%2F..%2F..%2Fbody-files%2Ffile1');
      expect(body).to.contain(relativeError);
    })
    .finally(() => {
      process.emit('SIGINT');
    })
    .it(
      'should get the file content with a relative path from the environment file, allow templated paths within their static base and prevent templated path traversal',
      (context) => {
        expect(context.stdout).to.contain('Server started');
      }
    );

  test
    .stdout()
    .do(() => {
      const content = readFileSync('./test/data/envs/file.json', 'utf-8');
      const environment = JSON.parse(content);
      const envsDirectory = resolve('./test/data/envs');
      const [, param1Route, param2Route] = environment.routes;
      const urlParam = "{{urlParam 'filename'}}";

      environment.port = 3010;
      // templated absolute path with a static base directory
      param1Route.responses[0].filePath = `${envsDirectory}/${urlParam}`;
      // fully templated path
      param2Route.responses[0].filePath = urlParam;

      writeFileSync(absoluteEnvPath, JSON.stringify(environment));
    })
    .command(['start', '--data', absoluteEnvPath, '--disable-log-to-file'])
    .do(async () => {
      const outsideFile = resolve('./test/data/body-files/file1.txt');
      const encodedOutsideFile = encodeURIComponent(outsideFile);
      let body: string;

      // templated absolute path inside its static base directory
      body = await getBody(3010, '/param1/mock1.json');
      expect(body).to.contain('"name": "mock1"');

      // templated absolute path escaping its static base directory
      body = await getBody(3010, '/param1/..%2Fbody-files%2Ffile1.txt');
      expect(body).to.contain(absoluteError);
      expect(body).to.not.contain('filecontent');

      // fully templated absolute path (no allowed base directory)
      body = await getBody(3010, `/param2/${encodedOutsideFile}`);
      expect(body).to.contain(rootError);
      expect(body).to.not.contain('filecontent');
    })
    .finally(() => {
      process.emit('SIGINT');
      rmSync(absoluteEnvPath, { force: true });
    })
    .it(
      'should get the file content with an absolute path and prevent templated path traversal',
      (context) => {
        expect(context.stdout).to.contain('Server started');
      }
    );
});
