--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## (KMPlayer 64X Subtitles Parser Integer Overflow Vulnerability)


### Affected Software

KMPlayer 2018.12.24.14 KMP 64X

#### Severity of the bug

Low

#### Description of the vulnerability

When processing the subtitle file, KMPlayer doesn't check the Object size correctly, which leads to integer overflow and memory out-of-bounds read.

#### Technical Details

Crash Context is inside memmove() function:

~~~shell
0:019> g
(564.2b14): Access violation - code c0000005 (!!! first chance !!!)
KMPlayer64+0x5015b7:
00007ff6`2a6015b7 f3a4            rep movs byte ptr [rdi],byte ptr [rsi]
0:019> r
rax=0000024d95c42c85 rbx=000000964aeff980 rcx=fffffffffffac33c
rdx=00000000033486bb rsi=0000024d98fdf000 rdi=0000024d95c96945
rip=00007ff62a6015b7 rsp=000000964aeff8e8 rbp=0000000000000001
 r8=0000024d95d29350  r9=0000000000000000 r10=0000024d98f8b340
r11=fffffffffffffffc r12=0000000000000003 r13=0000000000000000
r14=0000000000000000 r15=0000000000000000
iopl=0         nv up ei ng nz na pe cy
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010281
KMPlayer64+0x5015b7:
00007ff6`2a6015b7 f3a4            rep movs byte ptr [rdi],byte ptr [rsi]
~~~

The program will try to parse the subtitle file with the parser of any subtitle type which is supported.

Then its come to the ***.sup*** file format parser

~~~C
__int64 __fastcall CPGSSubFile::ParseFile(struct_v3 *a1, __int64 a2)
{

....    
    std::vector(&v30, wLenSegment + 3);
    segBuff = v30;
    *v30 = v36;
    *(segBuff + 2) = v37;
    if ( !wLenSegment || CFile::Read(&fd, (segBuff + 3), wLenSegment) == wLenSegment )
    {
     CPGSSubFile->vtable->ParseSample(CPGSSubFile, v12, v16, segBuff, wLenSegment + 3);
        if ( !CPGSSubFile->byte636D0 )
            goto LABEL_3;
    }

....                
                
}
~~~

Note that I have declared the function name ***CPGSSubFile::ParseFile*** because the original binary was stripped, the offset of the function is 0x24BD30.

Dig into ***CPGSSubFile->vtable->ParseSample*** function (offset 0x249DC0):

~~~c
signed __int64 __fastcall PGS::ParseSample(struct_a1 *CPGSSub:OBJECT, __int64 a2, __int64 a3, __int64 a4)
{

....    
    
      m_nSegSize = CPGSSub:OBJECT->m_nSegSize;
      if ( CPGSSub:OBJECT->qword88 >= m_nSegSize )
      {
        pGBuffer = CPGSSub:OBJECT->pvoid78;
        v34 = m_nSegSize;
        v35 = 0i64;
        v36 = 0i64;
        v37 = 0i64;
        switch ( CPGSSub:OBJECT->m_nCurSegment )
        {
          case 0x14:
            ParsePalette(CPGSSub:OBJECT, &pGBuffer, m_nSegSize);
            break;
          case 0x15:
            ParseObject(CPGSSub:OBJECT, &pGBuffer, m_nSegSize);
            break;
          case 0x16:


....        
        
}
~~~

The bug occurs in ***ParseObject(this->CPGSSub:OBJECT, &pGBuffer, m_nSegSize)*** function (offset 0x24AD80) where the program set or append data to a RLE Object in the Object list:

~~~C
unsigned __int64 __fastcall ParseObject(__int64 this, _QWORD *pGBuffer, __int64 nUnitSize)
{

....    
    
  if ( v24 >= 0 )
  {
    pos = pObject->position;
    i = pos + nUnitSize - 4;
    if ( i <= pObject->buffer_size )
    {
      i = memmove((pObject->buffer + pos), (*pGBuffer + pGBuffer[2]), nUnitSize - 4);
      pObject->position += nUnitSize - 4;
    }
  }

....    
    
}
~~~

The ***pGBuffer*** array is the content of the subtitle file, so we totally control the array value. When appending data to an existed object, the following check is performed:

~~~c
    pos = pObject->position;
    i = pos + nUnitSize - 4;
    if ( i <= pObject->buffer_size )
    {
      i = memmove((pObject->buffer + pos), (*pGBuffer + pGBuffer[2]), nUnitSize - 4);
      pObject->position += nUnitSize - 4;
    }
~~~

Its check if the new position after the appending is larger than the size of the object, but the size of the new data is our choice then we can pick a number that overflow the expression ***pos + nUnitSize - 4*** and bypass the ***buffer_size*** check:

 * The ***pos*** variable is the current position of  the object that initialized by the size of the segment.
 * The ***nUnitSize*** variable is from the subtitle content, so we can set this variable to a value smaller than 4, then the result of ***pos + nUnitSize - 4*** is pretty small and pass the check, but the size when do the ***memmove*** is the result of ***nUnitSize - 4***, its so huge and crash the program.

#### CVE

 * [CVE-2019-9133](https://www.boho.or.kr/krcert/secNoticeView.do?bulletin_writing_sequence=34991)