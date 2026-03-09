package st.ana.accounts.oauth.server.controller;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;
import st.ana.accounts.oauth.server.dto.OAuthRequests;
import st.ana.accounts.oauth.server.dto.OAuthResponses;
import st.ana.accounts.oauth.server.model.OAuthClient;
import st.ana.accounts.oauth.server.repository.OAuthClientRepository;
import st.ana.accounts.oauth.server.service.OAuthClientService;

@RestController
@RequestMapping("/api/mgnt/oauth/clients")
@PreAuthorize("hasAuthority('MASTERCODE')")
@RequiredArgsConstructor
public class OAuthManagementController {

    private final OAuthClientRepository clientRepository;
    private final OAuthClientService clientService;
    private final ObjectMapper objectMapper;

    @GetMapping
    public List<OAuthResponses.OAuthClientResponse> getClients() {
        return clientRepository.findAll()
                .stream()
                .map(c -> toResponse(c, false))
                .toList();
    }

    @GetMapping("/{id}")
    public OAuthResponses.OAuthClientResponse getClient(@PathVariable String id) {
        return clientRepository.findById(id)
                .map(c -> toResponse(c, false))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }

    @PostMapping
    public ResponseEntity<OAuthResponses.OAuthClientResponse> createClient(@RequestBody OAuthRequests.CreateClientRequest req) {
        String id = clientService.generateClientId();
        OAuthClient built = buildFromCreate(id, req);
        OAuthClient saved = clientService.upsertClient(id, built);
        return ResponseEntity.status(HttpStatus.CREATED).body(toResponse(saved, true));
    }

    @PutMapping("/{id}")
    public OAuthResponses.OAuthClientResponse updateClient(@PathVariable String id, @RequestBody OAuthRequests.UpdateClientRequest req) {
        OAuthClient existing = clientRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        applyUpdate(existing, req);
        return toResponse(clientRepository.save(existing), false);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteClient(@PathVariable String id) {
        if (!clientRepository.existsById(id)) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        clientRepository.deleteById(id);
    }

    @PostMapping("/{id}/rotate-secret")
    public OAuthResponses.OAuthClientResponse rotateSecret(@PathVariable String id) {
        OAuthClient client = clientRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        String rawSecret = clientService.generateClientSecret();
        client.setSecret(clientService.encodeSecret(rawSecret));
        clientRepository.save(client);
        client.setSecret(rawSecret);
        return toResponse(client, true);
    }

    private OAuthClient buildFromCreate(String id, OAuthRequests.CreateClientRequest req) {
        try {
            return OAuthClient.builder()
                    .id(id)
                    .name(req.name())
                    .scopes(req.scopes())
                    .redirectUris(req.redirectUris())
                    .postLogoutRedirectUris(req.postLogoutRedirectUris())
                    .authenticationMethods(req.authenticationMethods())
                    .authorizationGrantTypes(req.authorizationGrantTypes())
                    .allowedRoles(req.allowedRoles())
                    .amsRefer(req.amsRefer())
                    .clientSettings(objectMapper.writeValueAsString(req.clientSettings()))
                    .tokenSettings(objectMapper.writeValueAsString(req.tokenSettings()))
                    .build();
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    private void applyUpdate(OAuthClient client, OAuthRequests.UpdateClientRequest req) {
        try {
            client.setName(req.name());
            client.setScopes(req.scopes());
            client.setRedirectUris(req.redirectUris());
            client.setPostLogoutRedirectUris(req.postLogoutRedirectUris());
            client.setAuthenticationMethods(req.authenticationMethods());
            client.setAuthorizationGrantTypes(req.authorizationGrantTypes());
            client.setAllowedRoles(req.allowedRoles());
            client.setAmsRefer(req.amsRefer());
            client.setClientSettings(objectMapper.writeValueAsString(req.clientSettings()));
            client.setTokenSettings(objectMapper.writeValueAsString(req.tokenSettings()));
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    private OAuthResponses.OAuthClientResponse toResponse(OAuthClient client, boolean includeSecret) {
        return new OAuthResponses.OAuthClientResponse(
                client.getId(),
                client.getName(),
                includeSecret ? client.getSecret() : null,
                client.getScopes(),
                client.getRedirectUris(),
                client.getPostLogoutRedirectUris(),
                client.getAuthenticationMethods(),
                client.getAuthorizationGrantTypes(),
                client.getAllowedRoles(),
                client.getAmsRefer()
        );
    }
}
