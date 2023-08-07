---
layout: single
title:  "OSEP Review"
date:   2023-08-01 19:23:50 -0500
categories: red-team
tags: osep
permalink: /:categories/:title/

header:
  overlay_image: /images/cloudflare1/banner.png
  overlay_filter: rgba(0, 0, 0, 0.7)
  actions:
     - label: "View Code"
       url: ""  
---

This is the first non-technical post I've written on the blog, and I'm going to talk about my impressions of the [OSEP](https://www.offsec.com/courses/pen-300/) certification offered by Offensive Security. I will tell you how the labs were, the exam process and I will leave you with some tips that were at least useful for me to face the exam.

In summary, my experience with the certification has been very good, I learnt the concepts of AV evasion and AD exploitation and put them into practice in a very real environment; all the tactics and techniques used could be used in a Red Team scenario.

## Labs
There is ~one lab per chapter, and the labs are a good way to practise the theory in the book. The labs also contain six different challenges to put you in an exam perspective, I would recommend doing all of them before the final exam. If you can do them on your own, without any help, you will probably have a chance of passing the exam. The exam is a challenge that cannot be passed by following a guide, so don't be overconfident.

> The exam is much more difficult than the [OSCP](https://www.offsec.com/courses/pen-200/), making the OSCP a more than necessary requirement in my opinion.

## Exam (~56h)
I started the exam on the 21st of July at 10:00am, I was there an hour before to make sure that the Kali VM was working properly and to test the two internet connections. 

> In my case, my main Internet line goes down during the day, so it was essential to have a mobile phone that offered a constant access point.

During the first morning I was able to get 3 flags (`12:39`, `13:03`, `13:55`), one of them I didn't expect to get so fast and it motivated me a lot. I stopped for lunch at 16:00 and ate in front of the computer. At `18:24` I already had 4 flags. 
I was stuck on one for a long time until ~20:00, so I took a shower and went for a walk with my girlfriend, this time of disconnection helped me a lot because when I arrived at ~21:00 I saw everything with a new vision. I stopped for dinner and at ~21:30 and I went back to face the flag I had been stuck on for so long at ~22:15. At `3:23` I got the flag and at `3:45` I had got another one, I documented everything and went to bed at ~5:00, with 6 flags already. There were only 4 more to go.

The second day I started at ~8:00, I hadn't slept much (~3h). During the second morning I got 3 more flags, 9 in total (`10:50`, `10:58`, `11:42`), only 1 more to go. I was hoping to get it before lunch, but no way. Finally I didn't eat that day and got the 10th flag at `19:18` in the afternoon, at `19:52` I had the 11th flag after ~33h.
After that, I had a good rest on the couch and a quiet dinner before checking that I had everything I needed for the next day's report.

On the third day, the last day, I got up around 10am and started writing the report, as I had already written down the screenshots and the procedure for each machine, I just needed to make it nice and detailed.

```python
| Time   | Event                                                  | Flags |
|--------|--------------------------------------------------------|-------|
| 10:00  | Started the exam                                       |   0   |
| 12:39  | Got 1st flag                                           |   1   |
| 13:03  | Got 2nd flag                                           |   2   |
| 13:55  | Got 3rd flag                                           |   3   |
| 16:00  | Stopped for lunch                                      |       |
| 18:24  | Got 4th flag                                           |   4   |
| 20:00  | Took a shower and went for a walk                      |       |
| 21:30  | Stopped for dinner                                     |       |
| 22:30  | Resumed work on the stuck flag                         |       |
| 3:23   | Got 5th flag                                           |   5   |
| 3:45   | Got 6th flag                                           |   6   |
| 5:00   | Went to bed                                            |       |
| 8:00   | Started the second day                                 |       |
| 10:50  | Got 7th flag                                           |   7   |
| 10:58  | Got 8th flag                                           |   8   |
| 11:42  | Got 9th flag                                           |   9   |
| 19:18  | Got 10th flag                                          |  10   |
| 19:52  | Got 11th flag                                          |  11   |
| 10:00  | Started the report on the third day                    |  11   |
| 18:00  | Finished the exam                                      |  11   |
```

I received my note 9 days later (including weekend).
## Tips
- If you are stuck on a flag, or think you are on the right path but have been stuck for a long time, go outside, take a walk, play with your dog, take a shower... and come back with fresh ideas.
- In my exam case, there were two ways to complete the exam, if you get stuck in one for too long, go to the other.
- There are two days for the practical part and one day for the report, so plan your sleep/meal times.
- Get up from the computer, my back hurts a lot from sitting for so long, stretch your legs.
- Take notes and screenshots of each step. Personally, I used [Obsidian](https://obsidian.md/) and [Flameshot](https://flameshot.org/).
- Make a write-up of each challenge and save the commands for a quick search.
- Don't be afraid to restart the environment, but make sure you have documented how to get access.
- Use common ports on reverse shells, such as ports 53, 80, 443. Other traffic may be blocked.
- Test the reverse shells or exploits with simple pings or HTTP requests, the AV may delete the binary/webshell/etc. If it works, try to `upx` the binary or adding some cipher to bypass the AV *(Caesar and XOR ciphers, time delays)*.
- If you are using a socks proxy to access another network, use [chisel](https://github.com/jpillora/chisel) and make sure the connection is stable.  `auxiliary/server/socks_proxy`  from Metasploit it's too slow.
- Have the tools shown in the book pre-compiled and test them in the challenges.
- Coffee.

## Recommended links
- [https://book.hacktricks.xyz/welcome/readme](https://book.hacktricks.xyz/welcome/readme)
- [https://steffinstanly.gitbook.io/osep-notes/](https://steffinstanly.gitbook.io/osep-notes/)
- [https://github.com/chvancooten/OSEP-Code-Snippets](https://github.com/chvancooten/OSEP-Code-Snippets)
- [https://notes.morph3.blog/](https://notes.morph3.blog/)
