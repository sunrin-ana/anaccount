package st.ana.accounts.user.dto;

import lombok.Builder;

public final class UserRequests {
    @Builder
    public static record UserRegisterRequest(String id, String googleId, String email, String name, String nickname, String phoneNumber) { }
}
