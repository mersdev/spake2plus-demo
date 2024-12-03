package com.xdman.spake2plus_demo.controller;

import com.xdman.spake2plus_demo.api.Spake2PlusApi;
import com.xdman.spake2plus_demo.model.*;
import com.xdman.spake2plus_demo.service.Spake2PlusService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/spake2plus")
public class Spake2PlusController implements Spake2PlusApi {

    private final Spake2PlusService spake2PlusService;

    @Autowired
    public Spake2PlusController(Spake2PlusService spake2PlusService) {
        this.spake2PlusService = spake2PlusService;
    }

    // Step 1: Verifier initiates the key exchange
    @PostMapping("/initiate")
    @Override
    public ResponseEntity<Spake2PlusRequest> initiateKeyExchange(
            @RequestParam String vehicleBrand) {
        try {
            Spake2PlusRequest request = spake2PlusService.initiateKeyExchange(vehicleBrand);
            return ResponseEntity.ok(request);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }

    // Step 2: Prover processes the request and responds
    @PostMapping("/respond")
    @Override
    public ResponseEntity<Spake2PlusResponse> processRequest(
            @RequestBody Spake2PlusRequest request,
            @RequestParam String password) {
        try {
            Spake2PlusResponse response = spake2PlusService.processRequest(request, password);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }

    // Step 3: Verifier verifies prover's response and sends evidence
    @PostMapping("/verify")
    @Override
    public ResponseEntity<Spake2PlusVerify> verifyAndGenerateEvidence(
            @RequestBody byte[] proverX) {
        try {
            Spake2PlusVerify verify = spake2PlusService.verifyAndGenerateEvidence(proverX);
            return ResponseEntity.ok(verify);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }

    // Step 4: Prover verifies and sends final response
    @PostMapping("/verify-response")
    @Override
    public ResponseEntity<Spake2PlusVerifyResponse> verifyAndGenerateFinalResponse(
            @RequestBody Spake2PlusVerify verify) {
        try {
            Spake2PlusVerifyResponse response = spake2PlusService.verifyAndGenerateFinalResponse(verify);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }

    // Step 5: Final verification by Verifier
    @PostMapping("/final-verify")
    @Override
    public ResponseEntity<Void> finalVerification(
            @RequestBody byte[] proverEvidence) {
        try {
            spake2PlusService.finalVerification(proverEvidence);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }
}
