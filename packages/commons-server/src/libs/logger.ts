import {
  createLogger,
  format as logFormat,
  Logger,
  transports as logsTransports
} from 'winston';
import {
  ConsoleTransportInstance,
  FileTransportInstance,
  FileTransportOptions
} from 'winston/lib/winston/transports';

export const createLoggerInstance = (
  fileTransportOptions?: FileTransportOptions | null
): Logger => {
  const transportsInstances: (
    | FileTransportInstance
    | ConsoleTransportInstance
  )[] = [new logsTransports.Console({ handleExceptions: true })];

  if (fileTransportOptions) {
    const fileTransport = new logsTransports.File({
      ...fileTransportOptions,
      handleExceptions: true
    });
    // Swallow late "write after end" errors after the server's transport is closed (crashes mocha on Windows)
    fileTransport.on('error', () => {});
    (fileTransport as unknown as { _stream?: NodeJS.EventEmitter })._stream?.on(
      'error',
      () => {}
    );

    transportsInstances.push(fileTransport);
  }

  return createLogger({
    level: 'info',
    format: logFormat.combine(logFormat.timestamp(), logFormat.json()),
    transports: transportsInstances,
    exitOnError: false
  });
};
