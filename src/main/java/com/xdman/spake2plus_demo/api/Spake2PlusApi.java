package com.xdman.spake2plus_demo.api;

import com.xdman.spake2plus_demo.model.*;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Tag(name = "SPAKE2+ Key Exchange", description = "API endpoints for SPAKE2+ key exchange protocol")
public interface Spake2PlusApi {

    @Operation(summary = "Initiate SPAKE2+ key exchange",
            description = "Verifier initiates the key exchange process by providing vehicle brand and receiving configuration parameters")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successfully initiated key exchange",
                    content = @Content(schema = @Schema(implementation = Spake2PlusRequest.class))),
            @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @PostMapping("/initiate")
    ResponseEntity<Spake2PlusRequest> initiateKeyExchange(
            @Parameter(description = "Vehicle brand for the key exchange", required = true)
            @RequestParam String vehicleBrand);

    @Operation(summary = "Process SPAKE2+ request",
            description = "Prover processes the initial request and generates public share X")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successfully processed request",
                    content = @Content(schema = @Schema(implementation = Spake2PlusResponse.class))),
            @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @PostMapping("/respond")
    ResponseEntity<Spake2PlusResponse> processRequest(
            @Parameter(description = "SPAKE2+ request parameters", required = true)
            @RequestBody Spake2PlusRequest request,
            @Parameter(description = "Password for key derivation", required = true)
            @RequestParam String password);

    @Operation(summary = "Verify prover's response",
            description = "Verifier verifies prover's public share X and generates Y and evidence M")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successfully verified response",
                    content = @Content(schema = @Schema(implementation = Spake2PlusVerify.class))),
            @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @PostMapping("/verify")
    ResponseEntity<Spake2PlusVerify> verifyAndGenerateEvidence(
            @Parameter(description = "Prover's public share X", required = true)
            @RequestBody byte[] proverX);

    @Operation(summary = "Process verifier's verification",
            description = "Prover verifies Y and M, then generates final evidence")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successfully processed verification",
                    content = @Content(schema = @Schema(implementation = Spake2PlusVerifyResponse.class))),
            @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @PostMapping("/verify-response")
    ResponseEntity<Spake2PlusVerifyResponse> verifyAndGenerateFinalResponse(
            @Parameter(description = "Verifier's public share Y and evidence M", required = true)
            @RequestBody Spake2PlusVerify verify);

    @Operation(summary = "Final verification",
            description = "Verifier performs final verification of prover's evidence")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successfully completed verification"),
            @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @PostMapping("/final-verify")
    ResponseEntity<Void> finalVerification(
            @Parameter(description = "Prover's evidence", required = true)
            @RequestBody byte[] proverEvidence);
}
