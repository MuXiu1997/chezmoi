package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/go-github/v40/github"
)

type gitHubData struct {
	keysCache map[string][]*github.Key
	repoCache map[string]map[string]*github.Repository
}

func (c *Config) gitHubKeysTemplateFunc(user string) []*github.Key {
	if keys, ok := c.gitHub.keysCache[user]; ok {
		return keys
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	gitHubClient := newGitHubClient(ctx)

	var allKeys []*github.Key
	opts := &github.ListOptions{
		PerPage: 100,
	}
	for {
		keys, resp, err := gitHubClient.Users.ListKeys(ctx, user, opts)
		if err != nil {
			returnTemplateError(err)
			return nil
		}
		allKeys = append(allKeys, keys...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	if c.gitHub.keysCache == nil {
		c.gitHub.keysCache = make(map[string][]*github.Key)
	}
	c.gitHub.keysCache[user] = allKeys

	return allKeys
}

func (c *Config) gitHubRepoTemplateFunc(userRepo string) *github.Repository {
	fields := strings.SplitN(userRepo, "/", 2)
	if len(fields) != 2 || fields[0] == "" || fields[1] == "" {
		returnTemplateError(fmt.Errorf("%s: not a user/repo", userRepo))
		return nil
	}
	user, repo := fields[0], fields[1]

	if repository := c.gitHub.repoCache[user][repo]; repository != nil {
		return repository
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	gitHubClient := newGitHubClient(ctx)

	repository, _, err := gitHubClient.Repositories.Get(ctx, user, repo)
	if err != nil {
		returnTemplateError(err)
		return nil
	}

	if c.gitHub.repoCache == nil {
		c.gitHub.repoCache = make(map[string]map[string]*github.Repository)
	}
	if c.gitHub.repoCache[user] == nil {
		c.gitHub.repoCache[user] = make(map[string]*github.Repository)
	}
	c.gitHub.repoCache[user][repo] = repository

	return repository
}
