import { BodyTypes, Environment, ServerErrorCodes } from '@mockoon/commons';
import { expect } from 'chai';
import { promises as fs } from 'fs';
import { get as httpGet } from 'http';
import { isAbsolute, resolve, sep } from 'path';
import { MockoonServer } from '../../../src';

const relativeError =
  'Access to relative path outside of the environment base directory';
const absoluteError =
  'Access to absolute path outside of the original static base directory';
const urlParam = "{{urlParam 'file'}}";
const queryParam = "{{queryParam 'file'}}";

// paths are OS dependent and must be built at runtime
const envDir = resolve('./test/data/environments');
const dataDir = resolve('./test/data');

async function getEnvironment(): Promise<Environment> {
  const environmentJson = await fs.readFile(
    './test/data/environments/test-env.json',
    'utf-8'
  );

  return JSON.parse(environmentJson) as Environment;
}

/**
 * Call the server's private getSafeFilePath method with a fake request.
 * Return the error message if the path is rejected.
 *
 * @param server
 * @param filePath
 * @param params - route params
 * @param query - query string params
 */
const safePath = (
  server: MockoonServer,
  filePath: string,
  params: Record<string, string> = {},
  query: Record<string, string> = {}
): string => {
  try {
    return (server as any).getSafeFilePath(filePath, { params, query });
  } catch (error: any) {
    return error.message;
  }
};

/**
 * Call the server and return the raw response body
 *
 * @param port
 * @param path
 */
const getBody = (port: number, path: string): Promise<string> =>
  new Promise((resolveBody, reject) => {
    const request = httpGet(`http://127.0.0.1:${port}${path}`, (response) => {
      let body = '';

      response.setEncoding('utf-8');
      response.on('data', (chunk) => {
        body += chunk;
      });
      response.on('end', () => resolveBody(body));
    });

    request.on('error', reject);
  });

describe('Server file serving path traversal', () => {
  let environment: Environment;

  before(async () => {
    environment = await getEnvironment();
  });

  describe('Relative paths', () => {
    let server: MockoonServer;

    before(() => {
      server = new MockoonServer(environment, { environmentDirectory: envDir });
    });

    it('should allow path traversal when the path is not templated', () => {
      const filePath = safePath(server, '../plain.data');

      expect(filePath).to.equal(resolve(envDir, '../plain.data'));
    });

    it('should resolve templated paths inside the environment directory', () => {
      const query = { file: 'a/b' };
      const filePath = safePath(server, `./${urlParam}`, { file: 'env.json' });
      const queryPath = safePath(server, `./${queryParam}`, {}, query);

      expect(filePath).to.equal(resolve(envDir, 'env.json'));
      expect(queryPath).to.equal(resolve(envDir, 'a/b'));
    });

    it('should prevent templated paths from escaping the environment directory', () => {
      const file = '../plain.data';
      const filePath = safePath(server, `./${urlParam}`, { file });
      const message = `${relativeError} (${resolve(envDir, file)})`;

      expect(filePath).to.equal(message);
    });

    it('should prevent all templated path traversal variants', () => {
      const files = [
        '..',
        '../plain.data',
        '../../../../../../../../etc/passwd',
        // leading (encoded) slash used in public exploits: %2F..%2F..%2F
        '/../../../../../../../../etc/passwd',
        'sub/../../plain.data',
        // sibling directory sharing the environment directory prefix
        '../environments-secret/secret.json'
      ];

      files.forEach((file) => {
        const templates = [`./${urlParam}`, "./{{{urlParam 'file'}}}"];

        templates.forEach((template) => {
          const filePath = safePath(server, template, { file });

          expect(filePath).to.contain(relativeError);
        });

        const queryPath = safePath(server, `./${queryParam}`, {}, { file });
        // fully templated paths can become absolute (e.g. leading slash)
        const fullPath = safePath(server, urlParam, { file });

        expect(queryPath).to.contain(relativeError);
        expect(fullPath).to.contain(
          isAbsolute(file) ? absoluteError : relativeError
        );
      });
    });

    it('should prevent the public exploit payload (encoded leading slash)', () => {
      const file = '/../../../../../../../../etc/passwd';
      const filePath = safePath(server, `./static/${urlParam}`, { file });

      expect(filePath).to.contain(relativeError);
    });

    it('should prevent templated paths with a static part outside of the environment directory', () => {
      const filePath = safePath(server, `../${urlParam}`, { file: 'a.json' });

      expect(filePath).to.contain(relativeError);
    });

    it('should prevent path traversal using backslashes', () => {
      const file = '..\\plain.data';
      const filePath = safePath(server, `./${urlParam}`, { file });

      if (sep === '\\') {
        expect(filePath).to.contain(relativeError);
      } else {
        // backslashes are valid file name characters on POSIX systems
        expect(filePath).to.equal(resolve(envDir, file));
      }
    });

    it('should resolve a relative environment directory before checking templated paths', () => {
      const relativeDirServer = new MockoonServer(environment, {
        environmentDirectory: './test/data/environments'
      });
      const template = `./${urlParam}`;

      const insidePath = safePath(relativeDirServer, template, {
        file: 'env.json'
      });
      const outsidePath = safePath(relativeDirServer, template, {
        file: '../plain.data'
      });

      expect(insidePath).to.equal(resolve(envDir, 'env.json'));
      expect(outsidePath).to.contain(relativeError);
    });

    it('should use the current working directory when no environment directory is provided', () => {
      const noDirServer = new MockoonServer(environment);

      const staticPath = safePath(noDirServer, '../outside.json');
      const insidePath = safePath(noDirServer, urlParam, { file: 'a.json' });
      const outsidePath = safePath(noDirServer, urlParam, {
        file: '../outside.json'
      });

      expect(staticPath).to.equal(resolve('../outside.json'));
      expect(insidePath).to.equal(resolve('a.json'));
      expect(outsidePath).to.contain(relativeError);
    });
  });

  describe('Absolute paths', () => {
    let server: MockoonServer;

    before(() => {
      server = new MockoonServer(environment, { environmentDirectory: envDir });
    });

    it('should allow path traversal when the path is not templated', () => {
      const filePath = safePath(server, `${dataDir}/../../package.json`);

      expect(filePath).to.equal(resolve(dataDir, '../../package.json'));
    });

    it('should resolve templated paths inside their static base directory', () => {
      const template = `${dataDir}/${urlParam}`;
      const partialTemplate = `${dataDir}/plain{{urlParam 'ext'}}`;

      const filePath = safePath(server, template, { file: 'plain.data' });
      const partialPath = safePath(server, partialTemplate, { ext: '.data' });

      expect(filePath).to.equal(resolve(dataDir, 'plain.data'));
      expect(partialPath).to.equal(resolve(dataDir, 'plain.data'));
    });

    it('should prevent templated paths from escaping their static base directory', () => {
      const file = '../../package.json';
      const filePath = safePath(server, `${dataDir}/${urlParam}`, { file });
      const message = `${absoluteError} (${resolve(dataDir, file)})`;

      expect(filePath).to.equal(message);
    });

    it('should prevent all templated path traversal variants', () => {
      const partialTemplate = `${dataDir}/plain{{urlParam 'ext'}}`;
      const files = [
        '..',
        '../../package.json',
        '../../../../../../../../etc/passwd',
        '/../../../../../../../../etc/passwd',
        'sub/../../package.json',
        // sibling directory sharing the static base directory prefix
        '../data-secret/secret.json'
      ];

      files.forEach((file) => {
        const filePath = safePath(server, `${dataDir}/${urlParam}`, { file });
        const partialPath = safePath(server, partialTemplate, {
          ext: `/../${file}`
        });

        expect(filePath).to.contain(absoluteError);
        expect(partialPath).to.contain(absoluteError);
      });
    });

    it('should prevent fully templated absolute paths', () => {
      const file = resolve(dataDir, 'plain.data');
      const filePath = safePath(server, urlParam, { file });

      expect(filePath).to.contain(absoluteError);
    });
  });

  describe('File serving', () => {
    const port = 3020;
    const errors: string[] = [];
    let server: MockoonServer;

    before(async () => {
      const servedEnvironment = await getEnvironment();
      const [relativeRoute, absoluteRoute] = servedEnvironment.routes;

      servedEnvironment.port = port;
      servedEnvironment.hostname = '127.0.0.1';
      relativeRoute.endpoint = 'relative/:file';
      relativeRoute.responses[0].bodyType = BodyTypes.FILE;
      relativeRoute.responses[0].sendFileAsBody = true;
      relativeRoute.responses[0].filePath = `./${urlParam}`;
      absoluteRoute.endpoint = 'absolute/:file';
      absoluteRoute.responses[0].bodyType = BodyTypes.FILE;
      absoluteRoute.responses[0].sendFileAsBody = true;
      absoluteRoute.responses[0].filePath = `${envDir}/${urlParam}`;

      server = new MockoonServer(servedEnvironment, {
        environmentDirectory: envDir
      });
      server.on('error', (errorCode, error) => {
        errors.push(`${errorCode}: ${error?.message}`);
      });

      await new Promise<void>((resolveStart) => {
        server.on('started', () => resolveStart());
        server.start();
      });
    });

    after(async () => {
      await new Promise<void>((resolveStop) => {
        server.on('stopped', () => resolveStop());
        server.stop();
      });
    });

    it('should serve templated files inside the allowed directories', async () => {
      const relativeBody = await getBody(port, '/relative/test-env.json');
      const absoluteBody = await getBody(port, '/absolute/test-env.json');

      expect(relativeBody).to.contain('"name": "Test env"');
      expect(absoluteBody).to.contain('"name": "Test env"');
    });

    it('should not serve files outside of the environment directory with a relative path', async () => {
      const body = await getBody(port, '/relative/..%2Fplain.data');

      expect(body).to.contain('Error while serving the content');
      expect(body).to.contain(relativeError);
      expect(body).to.not.contain('plainTest');
    });

    it('should not serve system files with an encoded path traversal', async () => {
      const exploit = '%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd';
      const body = await getBody(port, `/relative/${exploit}`);

      expect(body).to.contain(relativeError);
      expect(body).to.not.contain('root:');
    });

    it('should not serve files outside of the static base directory with an absolute path', async () => {
      const body = await getBody(port, '/absolute/..%2Fplain.data');
      const message = `${absoluteError} (${resolve(dataDir, 'plain.data')})`;
      const errorCode = ServerErrorCodes.ROUTE_SERVING_ERROR;

      expect(body).to.contain('Error while serving the content');
      expect(body).to.contain(message);
      expect(body).to.not.contain('plainTest');
      expect(errors).to.include(`${errorCode}: ${message}`);
    });
  });
});
