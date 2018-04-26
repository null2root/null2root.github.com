---
layout:        archive
title:         "g0g0g0 (0ctf quals) write-up"
subtitle:      "0ctf 2018 - g0g0g0 (Reverse, 343pt)"
author:        cheese
header-img:    "/posts-bg/post-bg-05.jpg"
category:      articles
tags:          [Write-up, reverse, ctf]
slack_channel: channel1
---


프로그램 실행에 따른 trace log 가 주어진다. 함수의 호출과 리턴이 Entering / Leaving 으로 명시되어 있고, 실행된 코드 또한 주어진다. 문제 이름과 같이 go 언어로 추정되며, 아래는 로그파일의 일부이다.

```
Entering main.main at /tmp/gogo.go:172:6.
.0:
	 t0 = new string (sa)
	 t1 = new string (sb)
	 t2 = new string (sc)
	 t3 = new [1]interface{} (varargs)
	 t4 = &t3[0:int]
	 t5 = make interface{} <- string ("Input 3 numbers":string)
	 *t4 = t5
	 t6 = slice t3[:]
	 t7 = fmt.Println(t6...)
Entering fmt.Println at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:256:6.
.0:
	 t0 = *os.Stdout
	 t1 = make io.Writer <- *os.File (t0)
	 t2 = Fprintln(t1, a...)
Entering fmt.Fprintln at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:245:6.
.0:
	 t0 = newPrinter()
```


주요 함수들은 main.{함수명} 의 이름으로 주어져 있으며, 이 규칙에 따라 함수들을 찾아보면

- main.main
- main.func0
- main.func1
- main.func2
- main.func3
- main.func4
- main.func5
- main.func6

과 같이 단순하게 구성되어 있음을 알 수 있다. go 언어에서의 phi 가 어떻게 동작하는 지 명확하지 않지만 for loop 의 역할을 한다고 보고 분석해 본 결과, 단순한 사칙연산을 10^n 자리별로 계산해 놓은 것임을 알 수 있었다.

결국 문제는 아래의 조건을 만족하는 경우 플래그를 출력한다.

```
a/(b+c)+b/(c+a)+c/(a+b) = 10
```

이 조건을 만족하는 온라인에서 찾아 인증하였다.

```
a=221855981602380704196804518854316541759883857932028285581812549404634844243737502744011549757448453135493556098964216532950604590733853450272184987603430882682754171300742698179931849310347

b=269103113846520710198086599018316928810831097261381335767926880507079911347095440987749703663156874995907158014866846058485318408629957749519665987782327830143454337518378955846463785600977

c=4862378745380642626737318101484977637219057323564658907686653339599714454790559130946320953938197181210525554039710122136086190642013402927952831079021210585653078786813279351784906397934209

flag{d0_You_l1k3_5Sa?cool~gogog0!}
```
