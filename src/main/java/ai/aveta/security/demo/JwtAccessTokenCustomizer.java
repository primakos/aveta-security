package ai.aveta.security.demo;

import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import javax.validation.constraints.NotNull;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;


public class JwtAccessTokenCustomizer implements Converter<Jwt, AbstractAuthenticationToken> {

	private final JwtGrantedAuthoritiesConverter defaultGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
	
	private static final String CLIENT_NAME_ELEMENT_IN_JWT = "resource_access";
	private static final String ROLE_ELEMENT_IN_JWT = "roles";
	private ObjectMapper mapper;
	  

    public JwtAccessTokenCustomizer(ObjectMapper mapper) {
    }

    @Override
    public AbstractAuthenticationToken convert(@NotNull final Jwt jwt) {
        Collection<GrantedAuthority> authorities = Stream
            .concat(defaultGrantedAuthoritiesConverter.convert(jwt).stream(), extractResourceRoles(jwt).stream())
            .collect(Collectors.toSet());           
        return new JwtAuthenticationToken(jwt, authorities);
    }
    
    private static Collection<? extends GrantedAuthority> extractResourceRoles(final Jwt jwt) {
        Collection<String> userRoles = jwt.getClaimAsStringList("roles");
        if (userRoles != null)
            return userRoles
                      .stream()
                      .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                      .collect(Collectors.toSet());
        return Collections.emptySet();
    }
    
    /**
     * Spring oauth2 expects roles under authorities element in tokenMap, 
     * but keycloak provides it under resource_access. Hence extractAuthentication
     * method is overriden to extract roles from resource_access.
     *
     * @return OAuth2Authentication with authorities for given application
     */
//    @Override
//    public OAuth2Authentication extractAuthentication(Map<String, ?> tokenMap) {
//      LOG.debug("Begin extractAuthentication: tokenMap = {}", tokenMap);
//      JsonNode token = mapper.convertValue(tokenMap, JsonNode.class);
//      Set<String> audienceList = extractClients(token); // extracting client names
//      List<GrantedAuthority> authorities = extractRoles(token); // extracting client roles
//
//      
//      OAuth2Authentication authentication = super.extractAuthentication(tokenMap);
//      OAuth2Request oAuth2Request = authentication.getOAuth2Request();
//
//      OAuth2Request request =
//          new OAuth2Request(oAuth2Request.getRequestParameters(), 
//              oAuth2Request.getClientId(), 
//              authorities, true, 
//              oAuth2Request.getScope(),
//              audienceList, null, null, null);
//
//      Authentication usernamePasswordAuthentication = 
//              new UsernamePasswordAuthenticationToken(authentication.getPrincipal(), 
//              "N/A", authorities);
//              
//      //LOG.debug("End extractAuthentication");
//      //return new
//      //return new OAuth2Authentication(request, usernamePasswordAuthentication);
//    }
//    
//    
//    private List<GrantedAuthority> extractRoles(JsonNode jwt) {
//        //LOG.debug("Begin extractRoles: jwt = {}", jwt);
//        Set<String> rolesWithPrefix = new HashSet<>();
//
//        jwt.path(CLIENT_NAME_ELEMENT_IN_JWT)
//            .elements()
//            .forEachRemaining(e -> e.path(ROLE_ELEMENT_IN_JWT)
//                .elements()
//                .forEachRemaining(r -> rolesWithPrefix.add("ROLE_" + r.asText())));
//
//        final List<GrantedAuthority> authorityList = 
//               AuthorityUtils.createAuthorityList(rolesWithPrefix.toArray(new String[0]));
//               
//        LOG.debug("End extractRoles: roles = {}", authorityList);
//        return authorityList;
//      }
    
    
    
}