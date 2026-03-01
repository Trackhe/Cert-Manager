/**
 * Dateipfade für CA-, Intermediate- und Leaf-Zertifikate.
 */
export function createPathHelpers(dataDir: string) {
  return {
    caKeyPath(caId: string): string {
      return `${dataDir}/ca-${caId}-key.pem`;
    },
    caCertPath(caId: string): string {
      return `${dataDir}/ca-${caId}-cert.pem`;
    },
    intermediateKeyPath(intermediateId: string): string {
      return `${dataDir}/intermediate-${intermediateId}-key.pem`;
    },
    intermediateCertPath(intermediateId: string): string {
      return `${dataDir}/intermediate-${intermediateId}-cert.pem`;
    },
    leafKeyPath(certificateId: number): string {
      return `${dataDir}/leaf-${certificateId}-key.pem`;
    },
    /** Zertifikat für den optionalen HTTPS-Server (Port+1). */
    serverHttpsCertPath(): string {
      return `${dataDir}/server-https-cert.pem`;
    },
    /** Schlüssel für den optionalen HTTPS-Server (Port+1). */
    serverHttpsKeyPath(): string {
      return `${dataDir}/server-https-key.pem`;
    },
  };
}

export type PathHelpers = ReturnType<typeof createPathHelpers>;
