package com.todaytrend.postservice.post.feign.user;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import java.util.List;

@FeignClient(name = "user-service", url ="3.38.107.1:10000")
public interface UserFeignClient {
    @GetMapping("api/users/server/uuid/{uuid}")
    UserFeignDto findImgAndNickname(@PathVariable("uuid")String uuid);

    @GetMapping("api/users/following-list/{uuid}")
    List<FollowUserVO> followingList(@PathVariable String uuid);
}
