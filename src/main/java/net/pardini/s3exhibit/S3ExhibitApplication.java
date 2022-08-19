package net.pardini.s3exhibit;

import com.amazonaws.auth.PEM;
import com.amazonaws.services.cloudfront.CloudFrontUrlSigner;
import com.amazonaws.services.cloudfront.util.SignerUtils;
import io.micrometer.core.annotation.Timed;
import lombok.Data;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.presigner.S3Presigner;
import software.amazon.awssdk.services.s3.presigner.model.GetObjectPresignRequest;

import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.PrivateKey;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

@SpringBootApplication
public class S3ExhibitApplication {
    public static void main(String[] args) {
        SpringApplication.run(S3ExhibitApplication.class, args);
    }
}

@org.springframework.stereotype.Controller
@Slf4j
class Controller {

    private final S3Properties s3Properties;

    private final CloudFrontProperties cloudFrontProperties;
    private final PrivateKey cloudFrontPK;

    public Controller(S3Properties s3Properties, CloudFrontProperties cloudFrontProperties) {
        this.s3Properties = s3Properties;
        this.cloudFrontProperties = cloudFrontProperties;
        log.info("Controller config: bucket: '{}', region: '{}' ({})", s3Properties.getBucket(), s3Properties.getRegion(), s3Properties.getRegion().metadata().description());
        log.info("Controller config: allowed first paths ({}): '{}'", s3Properties.getAllowedFirstPaths().size(), s3Properties.getAllowedFirstPaths());
        if (cloudFrontProperties != null && cloudFrontProperties.getDomain() != null && cloudFrontProperties.getKeyId() != null) {
            log.info("CloudFront config: domain: '{}' - keyID: '{}'", cloudFrontProperties.getDomain(), cloudFrontProperties.getKeyId());
            if (cloudFrontProperties.getKeyPEM() != null) {
                this.cloudFrontPK = loadCloudFrontPrivateKey(cloudFrontProperties.getKeyPEM());
                log.info("Loaded CloudFront private key with algo '{}'", cloudFrontPK.getAlgorithm());
            } else {
                this.cloudFrontPK = null;
                log.warn("CF private key is not configured, disabling CloudFront support");
            }
        } else {
            this.cloudFrontPK = null;
            log.warn("CloudFront not configured, disabling CF support");
        }
    }

    @SneakyThrows
    private PrivateKey loadCloudFrontPrivateKey(String base64EncodedPEMEncodedPK) {
        try (InputStream targetStream = new ByteArrayInputStream(Base64.decodeBase64(base64EncodedPEMEncodedPK))) {
            return PEM.readPrivateKey(targetStream);
        }
    }

    @GetMapping("/{firstDir}/**")
    @SneakyThrows
    @Timed(value = "redirector.request.duration")
    public ResponseEntity<String> request(@PathVariable String firstDir,
                                          HttpServletRequest request,
                                          @RequestParam(name = "proto", required = false, defaultValue = "https") String reqProto,
                                          @RequestParam(name = "via", required = false, defaultValue = "cf") String reqVia) {
        String bucketName = s3Properties.getBucket();
        String keyName = request.getRequestURI().substring(1); // remove first slash

        log.info("Got request - path '{}', firstDir: '{}', proto: '{}', via: '{}'", keyName, firstDir, reqProto, reqVia);
        if (!s3Properties.getAllowedFirstPaths().contains(firstDir)) {
            log.warn("First path not allowed: '{}' - allowed ones: '{}'", firstDir, s3Properties.getAllowedFirstPaths());
            return new ResponseEntity<>("not found", HttpStatus.NOT_FOUND);
        }

        if ("cf".equalsIgnoreCase(reqVia) && (cloudFrontPK != null)) {
            String cfSignedURL = CloudFrontUrlSigner.getSignedURLWithCannedPolicy(
                    SignerUtils.generateResourcePath(
                            ("http".equalsIgnoreCase(reqProto) ? SignerUtils.Protocol.http : SignerUtils.Protocol.https),
                            cloudFrontProperties.getDomain(),
                            keyName
                    ),
                    cloudFrontProperties.getKeyId(),
                    cloudFrontPK,
                    Date.from(LocalDateTime.now().plus(Duration.of(s3Properties.getDurationMinutes(), ChronoUnit.MINUTES)).atZone(ZoneId.of("Etc/UTC")).toInstant())
            );
            log.info("CloudFront signed URL: '{}'", cfSignedURL);
            return ResponseEntity.status(HttpStatus.FOUND).header(HttpHeaders.LOCATION, cfSignedURL).build();
        }

        log.debug("Fallback, using S3 presigner, via: '{}'", reqVia);
        try (S3Presigner presigner = S3Presigner.builder().credentialsProvider(() -> AwsBasicCredentials.create(s3Properties.getAccessKey(), s3Properties.getSecretKey())).region(s3Properties.getRegion()).build()) {
            String s3PresignedURL = presigner.presignGetObject(
                    GetObjectPresignRequest.builder()
                            .signatureDuration(Duration.ofMinutes(s3Properties.getDurationMinutes()))
                            .getObjectRequest(
                                    GetObjectRequest.builder()
                                            .bucket(bucketName)
                                            .key(keyName).build()
                            ).build()
            ).url().toString();
            log.info("S3 Presigned URL: '{}' ", s3PresignedURL);
            return ResponseEntity.status(HttpStatus.FOUND).header(HttpHeaders.LOCATION, s3PresignedURL).build();
        }
    }
}

@Configuration
@ConfigurationProperties(prefix = "s3")
@Data
class S3Properties {
    private Region region;
    private String bucket;
    private String accessKey;
    private String secretKey;
    private List<String> allowedFirstPaths;
    private Integer durationMinutes;
}


@Configuration
@ConfigurationProperties(prefix = "cloudfront")
@Data
class CloudFrontProperties {
    private String domain;
    private String keyId;
    private String keyPEM;
}
