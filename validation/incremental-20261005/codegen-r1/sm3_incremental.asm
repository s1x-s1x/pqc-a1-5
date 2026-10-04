
/home/guest-experiment/pqc-a1-5/validation/incremental-20261005/codegen-r1/sm3_incremental.o:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <expand>:
       0:	f3 0f 7e 6f 38       	movq   0x38(%rdi),%xmm5
       5:	f3 0f 7e 7f 30       	movq   0x30(%rdi),%xmm7
       a:	48 8d 57 34          	lea    0x34(%rdi),%rdx
       e:	48 8d 4f 40          	lea    0x40(%rdi),%rcx
      12:	f3 0f 7e 57 28       	movq   0x28(%rdi),%xmm2
      17:	b8 03 00 00 00       	mov    $0x3,%eax
      1c:	eb 0e                	jmp    2c <expand+0x2c>
      1e:	66 90                	xchg   %ax,%ax
      20:	66 0f 6f e8          	movdqa %xmm0,%xmm5
      24:	66 0f 6f f9          	movdqa %xmm1,%xmm7
      28:	66 0f 6f d6          	movdqa %xmm6,%xmm2
      2c:	f3 0f 7e 0a          	movq   (%rdx),%xmm1
      30:	48 89 d6             	mov    %rdx,%rsi
      33:	83 c0 03             	add    $0x3,%eax
      36:	4c 8d 42 e4          	lea    -0x1c(%rdx),%r8
      3a:	f3 0f 7e 5a e8       	movq   -0x18(%rdx),%xmm3
      3f:	49 89 d1             	mov    %rdx,%r9
      42:	48 89 cf             	mov    %rcx,%rdi
      45:	48 83 c2 18          	add    $0x18,%rdx
      49:	66 0f 6f c1          	movdqa %xmm1,%xmm0
      4d:	66 0f 72 d1 11       	psrld  $0x11,%xmm1
      52:	48 83 ee 10          	sub    $0x10,%rsi
      56:	48 83 c1 18          	add    $0x18,%rcx
      5a:	66 0f 72 f0 0f       	pslld  $0xf,%xmm0
      5f:	f3 0f 7e 62 c0       	movq   -0x40(%rdx),%xmm4
      64:	66 0f eb c1          	por    %xmm1,%xmm0
      68:	f3 0f 7e 4a b4       	movq   -0x4c(%rdx),%xmm1
      6d:	66 0f ef cb          	pxor   %xmm3,%xmm1
      71:	66 0f ef c1          	pxor   %xmm1,%xmm0
      75:	66 0f 6f c8          	movdqa %xmm0,%xmm1
      79:	66 0f 6f f0          	movdqa %xmm0,%xmm6
      7d:	66 44 0f 6f c0       	movdqa %xmm0,%xmm8
      82:	66 0f 72 d6 11       	psrld  $0x11,%xmm6
      87:	66 0f 72 f1 0f       	pslld  $0xf,%xmm1
      8c:	66 0f eb ce          	por    %xmm6,%xmm1
      90:	66 41 0f 72 f0 17    	pslld  $0x17,%xmm8
      96:	66 0f 6f f0          	movdqa %xmm0,%xmm6
      9a:	66 0f 72 d6 09       	psrld  $0x9,%xmm6
      9f:	66 41 0f eb f0       	por    %xmm8,%xmm6
      a4:	66 0f ef ce          	pxor   %xmm6,%xmm1
      a8:	66 0f 6f f4          	movdqa %xmm4,%xmm6
      ac:	66 0f 72 d6 19       	psrld  $0x19,%xmm6
      b1:	66 0f 72 f4 07       	pslld  $0x7,%xmm4
      b6:	66 0f eb f4          	por    %xmm4,%xmm6
      ba:	f3 0f 7e 62 c8       	movq   -0x38(%rdx),%xmm4
      bf:	66 0f ef f2          	pxor   %xmm2,%xmm6
      c3:	f3 0f 7e 52 bc       	movq   -0x44(%rdx),%xmm2
      c8:	66 0f ef f1          	pxor   %xmm1,%xmm6
      cc:	66 0f ef f0          	pxor   %xmm0,%xmm6
      d0:	f3 0f 7e 42 d8       	movq   -0x28(%rdx),%xmm0
      d5:	66 0f d6 72 f4       	movq   %xmm6,-0xc(%rdx)
      da:	f3 0f 7e 4a f0       	movq   -0x10(%rdx),%xmm1
      df:	66 0f ef c2          	pxor   %xmm2,%xmm0
      e3:	66 0f 6f d1          	movdqa %xmm1,%xmm2
      e7:	66 0f 72 f1 0f       	pslld  $0xf,%xmm1
      ec:	66 0f 72 d2 11       	psrld  $0x11,%xmm2
      f1:	66 0f eb ca          	por    %xmm2,%xmm1
      f5:	66 0f ef c1          	pxor   %xmm1,%xmm0
      f9:	66 0f 6f c8          	movdqa %xmm0,%xmm1
      fd:	66 0f 6f d0          	movdqa %xmm0,%xmm2
     101:	66 44 0f 6f c0       	movdqa %xmm0,%xmm8
     106:	66 0f 72 f2 0f       	pslld  $0xf,%xmm2
     10b:	66 0f 72 d1 11       	psrld  $0x11,%xmm1
     110:	66 0f eb ca          	por    %xmm2,%xmm1
     114:	66 41 0f 72 f0 17    	pslld  $0x17,%xmm8
     11a:	66 0f 6f d0          	movdqa %xmm0,%xmm2
     11e:	66 0f 72 d2 09       	psrld  $0x9,%xmm2
     123:	66 41 0f eb d0       	por    %xmm8,%xmm2
     128:	66 0f ef ca          	pxor   %xmm2,%xmm1
     12c:	66 0f 6f d4          	movdqa %xmm4,%xmm2
     130:	66 0f 72 d2 19       	psrld  $0x19,%xmm2
     135:	66 0f 72 f4 07       	pslld  $0x7,%xmm4
     13a:	66 0f eb d4          	por    %xmm4,%xmm2
     13e:	f3 0f 7e 62 e0       	movq   -0x20(%rdx),%xmm4
     143:	66 0f ef d7          	pxor   %xmm7,%xmm2
     147:	66 0f ef ca          	pxor   %xmm2,%xmm1
     14b:	f3 0f 7e 52 c4       	movq   -0x3c(%rdx),%xmm2
     150:	66 0f ef c8          	pxor   %xmm0,%xmm1
     154:	66 0f d6 4a fc       	movq   %xmm1,-0x4(%rdx)
     159:	f3 0f 7e 42 f8       	movq   -0x8(%rdx),%xmm0
     15e:	66 0f ef d4          	pxor   %xmm4,%xmm2
     162:	66 0f 6f e0          	movdqa %xmm0,%xmm4
     166:	66 0f 72 f0 0f       	pslld  $0xf,%xmm0
     16b:	66 0f 72 d4 11       	psrld  $0x11,%xmm4
     170:	66 0f eb c4          	por    %xmm4,%xmm0
     174:	66 0f ef d0          	pxor   %xmm0,%xmm2
     178:	66 0f 6f c2          	movdqa %xmm2,%xmm0
     17c:	66 0f 6f e2          	movdqa %xmm2,%xmm4
     180:	66 0f 6f fa          	movdqa %xmm2,%xmm7
     184:	66 0f 72 f4 0f       	pslld  $0xf,%xmm4
     189:	66 0f 72 d0 11       	psrld  $0x11,%xmm0
     18e:	66 0f eb c4          	por    %xmm4,%xmm0
     192:	66 0f 72 f7 17       	pslld  $0x17,%xmm7
     197:	66 0f 6f e2          	movdqa %xmm2,%xmm4
     19b:	66 0f 72 d4 09       	psrld  $0x9,%xmm4
     1a0:	66 0f eb e7          	por    %xmm7,%xmm4
     1a4:	66 0f ef c4          	pxor   %xmm4,%xmm0
     1a8:	66 0f 6f e3          	movdqa %xmm3,%xmm4
     1ac:	66 0f 72 d4 19       	psrld  $0x19,%xmm4
     1b1:	66 0f 72 f3 07       	pslld  $0x7,%xmm3
     1b6:	66 0f eb dc          	por    %xmm4,%xmm3
     1ba:	66 0f ef dd          	pxor   %xmm5,%xmm3
     1be:	66 0f ef c3          	pxor   %xmm3,%xmm0
     1c2:	66 0f ef c2          	pxor   %xmm2,%xmm0
     1c6:	66 0f d6 42 04       	movq   %xmm0,0x4(%rdx)
     1cb:	83 f8 1b             	cmp    $0x1b,%eax
     1ce:	0f 85 4c fe ff ff    	jne    20 <expand+0x20>
     1d4:	31 c0                	xor    %eax,%eax
     1d6:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
     1dd:	00 00 00 
     1e0:	f3 0f 7e 04 c2       	movq   (%rdx,%rax,8),%xmm0
     1e5:	f3 41 0f 7e 14 c1    	movq   (%r9,%rax,8),%xmm2
     1eb:	f3 41 0f 7e 0c c0    	movq   (%r8,%rax,8),%xmm1
     1f1:	f3 0f 7e 1c c6       	movq   (%rsi,%rax,8),%xmm3
     1f6:	66 0f ef ca          	pxor   %xmm2,%xmm1
     1fa:	66 0f 6f d0          	movdqa %xmm0,%xmm2
     1fe:	66 0f 72 d2 11       	psrld  $0x11,%xmm2
     203:	66 0f 72 f0 0f       	pslld  $0xf,%xmm0
     208:	66 0f eb c2          	por    %xmm2,%xmm0
     20c:	66 0f ef c8          	pxor   %xmm0,%xmm1
     210:	66 0f 6f c1          	movdqa %xmm1,%xmm0
     214:	66 0f 6f d1          	movdqa %xmm1,%xmm2
     218:	66 0f 6f e1          	movdqa %xmm1,%xmm4
     21c:	66 0f 72 f2 17       	pslld  $0x17,%xmm2
     221:	66 0f 72 d0 09       	psrld  $0x9,%xmm0
     226:	66 0f eb c2          	por    %xmm2,%xmm0
     22a:	66 0f 72 f4 0f       	pslld  $0xf,%xmm4
     22f:	66 0f 6f d1          	movdqa %xmm1,%xmm2
     233:	66 0f 72 d2 11       	psrld  $0x11,%xmm2
     238:	66 0f eb d4          	por    %xmm4,%xmm2
     23c:	66 0f ef c2          	pxor   %xmm2,%xmm0
     240:	66 0f 6f d3          	movdqa %xmm3,%xmm2
     244:	66 0f 72 d2 19       	psrld  $0x19,%xmm2
     249:	66 0f 72 f3 07       	pslld  $0x7,%xmm3
     24e:	66 0f eb d3          	por    %xmm3,%xmm2
     252:	f3 0f 7e 1c c7       	movq   (%rdi,%rax,8),%xmm3
     257:	66 0f ef d3          	pxor   %xmm3,%xmm2
     25b:	66 0f ef c2          	pxor   %xmm2,%xmm0
     25f:	66 0f ef c1          	pxor   %xmm1,%xmm0
     263:	66 0f d6 04 c1       	movq   %xmm0,(%rcx,%rax,8)
     268:	48 83 c0 01          	add    $0x1,%rax
     26c:	83 f8 01             	cmp    $0x1,%eax
     26f:	0f 84 6b ff ff ff    	je     1e0 <expand+0x1e0>
     275:	c3                   	ret    
     276:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
     27d:	00 00 00 

0000000000000280 <update8>:
     280:	48 8d 87 80 08 00 00 	lea    0x880(%rdi),%rax
     287:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
     28e:	00 00 
     290:	c4 e2 7d 58 06       	vpbroadcastd (%rsi),%ymm0
     295:	c5 fd ef 07          	vpxor  (%rdi),%ymm0,%ymm0
     299:	48 83 c7 20          	add    $0x20,%rdi
     29d:	48 83 c6 04          	add    $0x4,%rsi
     2a1:	c5 fe 7f 47 e0       	vmovdqu %ymm0,-0x20(%rdi)
     2a6:	48 39 f8             	cmp    %rdi,%rax
     2a9:	75 e5                	jne    290 <update8+0x10>
     2ab:	c5 f8 77             	vzeroupper 
     2ae:	c3                   	ret    
     2af:	90                   	nop

00000000000002b0 <expand8>:
     2b0:	48 89 fa             	mov    %rdi,%rdx
     2b3:	48 89 f0             	mov    %rsi,%rax
     2b6:	48 39 f7             	cmp    %rsi,%rdi
     2b9:	74 34                	je     2ef <expand8+0x3f>
     2bb:	48 8b 0f             	mov    (%rdi),%rcx
     2be:	48 89 0e             	mov    %rcx,(%rsi)
     2c1:	48 8b 8f f8 01 00 00 	mov    0x1f8(%rdi),%rcx
     2c8:	48 8d 7e 08          	lea    0x8(%rsi),%rdi
     2cc:	48 83 e7 f8          	and    $0xfffffffffffffff8,%rdi
     2d0:	48 89 8e f8 01 00 00 	mov    %rcx,0x1f8(%rsi)
     2d7:	48 89 f1             	mov    %rsi,%rcx
     2da:	48 89 d6             	mov    %rdx,%rsi
     2dd:	48 29 f9             	sub    %rdi,%rcx
     2e0:	48 29 ce             	sub    %rcx,%rsi
     2e3:	81 c1 00 02 00 00    	add    $0x200,%ecx
     2e9:	c1 e9 03             	shr    $0x3,%ecx
     2ec:	f3 48 a5             	rep movsq %ds:(%rsi),%es:(%rdi)
     2ef:	c5 7e 6f 48 40       	vmovdqu 0x40(%rax),%ymm9
     2f4:	c5 fe 6f 30          	vmovdqu (%rax),%ymm6
     2f8:	48 8d 50 60          	lea    0x60(%rax),%rdx
     2fc:	b9 10 00 00 00       	mov    $0x10,%ecx
     301:	c5 fe 6f 78 20       	vmovdqu 0x20(%rax),%ymm7
     306:	c5 fe 6f a8 20 01 00 	vmovdqu 0x120(%rax),%ymm5
     30d:	00 
     30e:	c5 fe 6f 98 00 01 00 	vmovdqu 0x100(%rax),%ymm3
     315:	00 
     316:	c5 fe 6f a0 e0 00 00 	vmovdqu 0xe0(%rax),%ymm4
     31d:	00 
     31e:	c5 fe 6f 80 e0 01 00 	vmovdqu 0x1e0(%rax),%ymm0
     325:	00 
     326:	c5 fe 6f 90 c0 01 00 	vmovdqu 0x1c0(%rax),%ymm2
     32d:	00 
     32e:	c5 fe 6f 88 a0 01 00 	vmovdqu 0x1a0(%rax),%ymm1
     335:	00 
     336:	eb 0c                	jmp    344 <expand8+0x94>
     338:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
     33f:	00 
     340:	c5 7d 7f c3          	vmovdqa %ymm8,%ymm3
     344:	c5 bd 72 d1 11       	vpsrld $0x11,%ymm1,%ymm8
     349:	c5 cd ef e4          	vpxor  %ymm4,%ymm6,%ymm4
     34d:	c5 fe 6f 32          	vmovdqu (%rdx),%ymm6
     351:	83 c1 03             	add    $0x3,%ecx
     354:	c5 f5 72 f1 0f       	vpslld $0xf,%ymm1,%ymm1
     359:	c5 e5 ef df          	vpxor  %ymm7,%ymm3,%ymm3
     35d:	c5 b5 ef ed          	vpxor  %ymm5,%ymm9,%ymm5
     361:	48 83 c2 60          	add    $0x60,%rdx
     365:	c4 c1 75 eb c8       	vpor   %ymm8,%ymm1,%ymm1
     36a:	c5 9d 72 d6 19       	vpsrld $0x19,%ymm6,%ymm12
     36f:	c5 fe 6f 7a c0       	vmovdqu -0x40(%rdx),%ymm7
     374:	c5 7e 6f 4a e0       	vmovdqu -0x20(%rdx),%ymm9
     379:	c5 dd ef c9          	vpxor  %ymm1,%ymm4,%ymm1
     37d:	c5 fe 6f a2 80 00 00 	vmovdqu 0x80(%rdx),%ymm4
     384:	00 
     385:	c5 ad 72 f6 07       	vpslld $0x7,%ymm6,%ymm10
     38a:	c5 95 72 d1 09       	vpsrld $0x9,%ymm1,%ymm13
     38f:	c5 8d 72 d1 11       	vpsrld $0x11,%ymm1,%ymm14
     394:	c5 a5 72 f1 17       	vpslld $0x17,%ymm1,%ymm11
     399:	c5 bd 72 f1 0f       	vpslld $0xf,%ymm1,%ymm8
     39e:	c5 dd ef c9          	vpxor  %ymm1,%ymm4,%ymm1
     3a2:	c4 41 25 eb dd       	vpor   %ymm13,%ymm11,%ymm11
     3a7:	c4 41 3d eb c6       	vpor   %ymm14,%ymm8,%ymm8
     3ac:	c4 41 3d ef c3       	vpxor  %ymm11,%ymm8,%ymm8
     3b1:	c5 bd ef c9          	vpxor  %ymm1,%ymm8,%ymm1
     3b5:	c4 41 2d eb c4       	vpor   %ymm12,%ymm10,%ymm8
     3ba:	c5 ad 72 d7 19       	vpsrld $0x19,%ymm7,%ymm10
     3bf:	c5 9d 72 f7 07       	vpslld $0x7,%ymm7,%ymm12
     3c4:	c4 c1 75 ef c8       	vpxor  %ymm8,%ymm1,%ymm1
     3c9:	c5 bd 72 d2 11       	vpsrld $0x11,%ymm2,%ymm8
     3ce:	c5 ed 72 f2 0f       	vpslld $0xf,%ymm2,%ymm2
     3d3:	c5 fe 7f 8a 40 01 00 	vmovdqu %ymm1,0x140(%rdx)
     3da:	00 
     3db:	c5 bd eb d2          	vpor   %ymm2,%ymm8,%ymm2
     3df:	c5 7e 6f 82 a0 00 00 	vmovdqu 0xa0(%rdx),%ymm8
     3e6:	00 
     3e7:	c5 e5 ef da          	vpxor  %ymm2,%ymm3,%ymm3
     3eb:	c5 95 72 f3 17       	vpslld $0x17,%ymm3,%ymm13
     3f0:	c5 8d 72 f3 0f       	vpslld $0xf,%ymm3,%ymm14
     3f5:	c5 a5 72 d3 09       	vpsrld $0x9,%ymm3,%ymm11
     3fa:	c5 ed 72 d3 11       	vpsrld $0x11,%ymm3,%ymm2
     3ff:	c5 bd ef db          	vpxor  %ymm3,%ymm8,%ymm3
     403:	c4 41 25 eb dd       	vpor   %ymm13,%ymm11,%ymm11
     408:	c4 c1 6d eb d6       	vpor   %ymm14,%ymm2,%ymm2
     40d:	c4 c1 6d ef d3       	vpxor  %ymm11,%ymm2,%ymm2
     412:	c5 ed ef d3          	vpxor  %ymm3,%ymm2,%ymm2
     416:	c4 c1 2d eb dc       	vpor   %ymm12,%ymm10,%ymm3
     41b:	c5 ad 72 d0 11       	vpsrld $0x11,%ymm0,%ymm10
     420:	c4 c1 1d 72 d1 19    	vpsrld $0x19,%ymm9,%ymm12
     426:	c5 ed ef d3          	vpxor  %ymm3,%ymm2,%ymm2
     42a:	c5 e5 72 f0 0f       	vpslld $0xf,%ymm0,%ymm3
     42f:	c5 fe 7f 92 60 01 00 	vmovdqu %ymm2,0x160(%rdx)
     436:	00 
     437:	c4 c1 65 eb da       	vpor   %ymm10,%ymm3,%ymm3
     43c:	c4 c1 2d 72 f1 07    	vpslld $0x7,%ymm9,%ymm10
     442:	c5 e5 ef dd          	vpxor  %ymm5,%ymm3,%ymm3
     446:	c5 fe 6f aa c0 00 00 	vmovdqu 0xc0(%rdx),%ymm5
     44d:	00 
     44e:	c5 8d 72 d3 09       	vpsrld $0x9,%ymm3,%ymm14
     453:	c5 fd 72 f3 17       	vpslld $0x17,%ymm3,%ymm0
     458:	c5 95 72 d3 11       	vpsrld $0x11,%ymm3,%ymm13
     45d:	c5 a5 72 f3 0f       	vpslld $0xf,%ymm3,%ymm11
     462:	c4 c1 7d eb c6       	vpor   %ymm14,%ymm0,%ymm0
     467:	c4 41 25 eb dd       	vpor   %ymm13,%ymm11,%ymm11
     46c:	c5 d5 ef db          	vpxor  %ymm3,%ymm5,%ymm3
     470:	c4 c1 7d ef c3       	vpxor  %ymm11,%ymm0,%ymm0
     475:	c5 fd ef c3          	vpxor  %ymm3,%ymm0,%ymm0
     479:	c4 c1 2d eb dc       	vpor   %ymm12,%ymm10,%ymm3
     47e:	c5 fd ef c3          	vpxor  %ymm3,%ymm0,%ymm0
     482:	c5 fe 7f 82 80 01 00 	vmovdqu %ymm0,0x180(%rdx)
     489:	00 
     48a:	83 f9 43             	cmp    $0x43,%ecx
     48d:	0f 85 ad fe ff ff    	jne    340 <expand8+0x90>
     493:	48 8d 90 60 06 00 00 	lea    0x660(%rax),%rdx
     49a:	48 8d 88 80 06 00 00 	lea    0x680(%rax),%rcx
     4a1:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
     4a8:	c5 fe 6f ba a0 01 00 	vmovdqu 0x1a0(%rdx),%ymm7
     4af:	00 
     4b0:	48 83 c2 20          	add    $0x20,%rdx
     4b4:	c5 f5 72 f7 0f       	vpslld $0xf,%ymm7,%ymm1
     4b9:	c5 fd 72 d7 11       	vpsrld $0x11,%ymm7,%ymm0
     4be:	c5 fe 6f 7a 40       	vmovdqu 0x40(%rdx),%ymm7
     4c3:	c5 fd eb c1          	vpor   %ymm1,%ymm0,%ymm0
     4c7:	c5 fd ef 42 e0       	vpxor  -0x20(%rdx),%ymm0,%ymm0
     4cc:	c5 fd ef 82 c0 00 00 	vpxor  0xc0(%rdx),%ymm0,%ymm0
     4d3:	00 
     4d4:	c5 ed 72 d7 19       	vpsrld $0x19,%ymm7,%ymm2
     4d9:	c5 e5 72 f7 07       	vpslld $0x7,%ymm7,%ymm3
     4de:	c5 dd 72 d0 09       	vpsrld $0x9,%ymm0,%ymm4
     4e3:	c5 d5 72 f0 17       	vpslld $0x17,%ymm0,%ymm5
     4e8:	c5 ed eb d3          	vpor   %ymm3,%ymm2,%ymm2
     4ec:	c5 f5 72 d0 11       	vpsrld $0x11,%ymm0,%ymm1
     4f1:	c5 cd 72 f0 0f       	vpslld $0xf,%ymm0,%ymm6
     4f6:	c5 dd eb e5          	vpor   %ymm5,%ymm4,%ymm4
     4fa:	c5 ed ef 92 20 01 00 	vpxor  0x120(%rdx),%ymm2,%ymm2
     501:	00 
     502:	c5 f5 eb ce          	vpor   %ymm6,%ymm1,%ymm1
     506:	c5 f5 ef cc          	vpxor  %ymm4,%ymm1,%ymm1
     50a:	c5 f5 ef ca          	vpxor  %ymm2,%ymm1,%ymm1
     50e:	c5 f5 ef c0          	vpxor  %ymm0,%ymm1,%ymm0
     512:	c5 fe 7f 82 e0 01 00 	vmovdqu %ymm0,0x1e0(%rdx)
     519:	00 
     51a:	48 39 ca             	cmp    %rcx,%rdx
     51d:	75 89                	jne    4a8 <expand8+0x1f8>
     51f:	c5 f8 77             	vzeroupper 
     522:	c3                   	ret    
     523:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
     52a:	00 00 00 00 
     52e:	66 90                	xchg   %ax,%ax

0000000000000530 <prepare_offsets>:
     530:	41 55                	push   %r13
     532:	41 54                	push   %r12
     534:	41 89 fc             	mov    %edi,%r12d
     537:	55                   	push   %rbp
     538:	53                   	push   %rbx
     539:	48 81 ec 48 03 00 00 	sub    $0x348,%rsp
     540:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
     547:	00 00 
     549:	48 89 84 24 38 03 00 	mov    %rax,0x338(%rsp)
     550:	00 
     551:	48 8d 05 00 00 00 00 	lea    0x0(%rip),%rax        # 558 <prepare_offsets+0x28>
     558:	4a 8d 1c a0          	lea    (%rax,%r12,4),%rbx
     55c:	8b 03                	mov    (%rbx),%eax
     55e:	83 f8 02             	cmp    $0x2,%eax
     561:	0f 84 f2 01 00 00    	je     759 <prepare_offsets+0x229>
     567:	31 c0                	xor    %eax,%eax
     569:	ba 01 00 00 00       	mov    $0x1,%edx
     56e:	f0 0f b1 13          	lock cmpxchg %edx,(%rbx)
     572:	0f 85 da 01 00 00    	jne    752 <prepare_offsets+0x222>
     578:	4c 89 e5             	mov    %r12,%rbp
     57b:	49 89 e3             	mov    %rsp,%r11
     57e:	4c 8d 94 24 30 03 00 	lea    0x330(%rsp),%r10
     585:	00 
     586:	41 bd 01 00 00 00    	mov    $0x1,%r13d
     58c:	89 e9                	mov    %ebp,%ecx
     58e:	44 89 ea             	mov    %r13d,%edx
     591:	31 c0                	xor    %eax,%eax
     593:	4c 89 df             	mov    %r11,%rdi
     596:	d3 e2                	shl    %cl,%edx
     598:	b9 22 00 00 00       	mov    $0x22,%ecx
     59d:	83 c5 01             	add    $0x1,%ebp
     5a0:	f3 48 ab             	rep stos %rax,%es:(%rdi)
     5a3:	89 d0                	mov    %edx,%eax
     5a5:	c1 e2 10             	shl    $0x10,%edx
     5a8:	4c 89 df             	mov    %r11,%rdi
     5ab:	c1 e8 10             	shr    $0x10,%eax
     5ae:	66 0f 6e f2          	movd   %edx,%xmm6
     5b2:	49 81 c3 10 01 00 00 	add    $0x110,%r11
     5b9:	66 0f 6e c0          	movd   %eax,%xmm0
     5bd:	66 0f 62 c6          	punpckldq %xmm6,%xmm0
     5c1:	66 41 0f d6 83 00 ff 	movq   %xmm0,-0x100(%r11)
     5c8:	ff ff 
     5ca:	e8 31 fa ff ff       	call   0 <expand>
     5cf:	4d 39 da             	cmp    %r11,%r10
     5d2:	75 b8                	jne    58c <prepare_offsets+0x5c>
     5d4:	4c 89 e0             	mov    %r12,%rax
     5d7:	48 8d 0d 00 00 00 00 	lea    0x0(%rip),%rcx        # 5de <prepare_offsets+0xae>
     5de:	48 8d 94 24 20 02 00 	lea    0x220(%rsp),%rdx
     5e5:	00 
     5e6:	48 c1 e0 04          	shl    $0x4,%rax
     5ea:	66 0f ef f6          	pxor   %xmm6,%xmm6
     5ee:	4c 01 e0             	add    %r12,%rax
     5f1:	48 c1 e0 07          	shl    $0x7,%rax
     5f5:	48 01 c8             	add    %rcx,%rax
     5f8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
     5ff:	00 
     600:	66 0f 6f 12          	movdqa (%rdx),%xmm2
     604:	66 0f 6f c6          	movdqa %xmm6,%xmm0
     608:	66 0f 6f fe          	movdqa %xmm6,%xmm7
     60c:	48 83 c2 10          	add    $0x10,%rdx
     610:	66 0f 6f 9a d0 fd ff 	movdqa -0x230(%rdx),%xmm3
     617:	ff 
     618:	66 0f 6f 8a e0 fe ff 	movdqa -0x120(%rdx),%xmm1
     61f:	ff 
     620:	48 83 e8 80          	sub    $0xffffffffffffff80,%rax
     624:	66 44 0f 6f c2       	movdqa %xmm2,%xmm8
     629:	66 44 0f 6f d2       	movdqa %xmm2,%xmm10
     62e:	66 44 0f 6f ca       	movdqa %xmm2,%xmm9
     633:	66 44 0f ef c3       	pxor   %xmm3,%xmm8
     638:	66 0f 6f e1          	movdqa %xmm1,%xmm4
     63c:	66 0f 6f eb          	movdqa %xmm3,%xmm5
     640:	66 0f ef e3          	pxor   %xmm3,%xmm4
     644:	66 44 0f ef d1       	pxor   %xmm1,%xmm10
     649:	66 41 0f 62 e8       	punpckldq %xmm8,%xmm5
     64e:	66 41 0f 6a d8       	punpckhdq %xmm8,%xmm3
     653:	66 44 0f 6f c1       	movdqa %xmm1,%xmm8
     658:	66 44 0f ef cc       	pxor   %xmm4,%xmm9
     65d:	66 45 0f 62 c2       	punpckldq %xmm10,%xmm8
     662:	66 41 0f 6a ca       	punpckhdq %xmm10,%xmm1
     667:	66 0f 62 c2          	punpckldq %xmm2,%xmm0
     66b:	66 44 0f 6f d4       	movdqa %xmm4,%xmm10
     670:	66 0f 6a fa          	punpckhdq %xmm2,%xmm7
     674:	66 0f 6f d0          	movdqa %xmm0,%xmm2
     678:	66 45 0f 62 d1       	punpckldq %xmm9,%xmm10
     67d:	66 41 0f 6a e1       	punpckhdq %xmm9,%xmm4
     682:	66 41 0f 62 d0       	punpckldq %xmm8,%xmm2
     687:	66 41 0f 6a c0       	punpckhdq %xmm8,%xmm0
     68c:	66 44 0f 6f cd       	movdqa %xmm5,%xmm9
     691:	66 44 0f 6f c7       	movdqa %xmm7,%xmm8
     696:	66 41 0f 6a ea       	punpckhdq %xmm10,%xmm5
     69b:	66 44 0f 62 c1       	punpckldq %xmm1,%xmm8
     6a0:	66 0f 6a f9          	punpckhdq %xmm1,%xmm7
     6a4:	66 45 0f 62 ca       	punpckldq %xmm10,%xmm9
     6a9:	66 0f 6f cd          	movdqa %xmm5,%xmm1
     6ad:	66 0f 6f eb          	movdqa %xmm3,%xmm5
     6b1:	66 0f 62 ec          	punpckldq %xmm4,%xmm5
     6b5:	66 0f 6a dc          	punpckhdq %xmm4,%xmm3
     6b9:	66 0f 6f e2          	movdqa %xmm2,%xmm4
     6bd:	66 41 0f 6a d1       	punpckhdq %xmm9,%xmm2
     6c2:	66 41 0f 62 e1       	punpckldq %xmm9,%xmm4
     6c7:	0f 29 50 90          	movaps %xmm2,-0x70(%rax)
     6cb:	66 0f 6f d0          	movdqa %xmm0,%xmm2
     6cf:	66 0f 6a c1          	punpckhdq %xmm1,%xmm0
     6d3:	0f 29 40 b0          	movaps %xmm0,-0x50(%rax)
     6d7:	66 41 0f 6f c0       	movdqa %xmm8,%xmm0
     6dc:	66 0f 62 d1          	punpckldq %xmm1,%xmm2
     6e0:	66 41 0f 6f c8       	movdqa %xmm8,%xmm1
     6e5:	66 0f 62 c5          	punpckldq %xmm5,%xmm0
     6e9:	66 0f 6a cd          	punpckhdq %xmm5,%xmm1
     6ed:	0f 29 60 80          	movaps %xmm4,-0x80(%rax)
     6f1:	0f 29 40 c0          	movaps %xmm0,-0x40(%rax)
     6f5:	66 0f 6f c7          	movdqa %xmm7,%xmm0
     6f9:	66 0f 6a fb          	punpckhdq %xmm3,%xmm7
     6fd:	66 0f 62 c3          	punpckldq %xmm3,%xmm0
     701:	0f 29 50 a0          	movaps %xmm2,-0x60(%rax)
     705:	0f 29 48 d0          	movaps %xmm1,-0x30(%rax)
     709:	0f 29 40 e0          	movaps %xmm0,-0x20(%rax)
     70d:	0f 29 78 f0          	movaps %xmm7,-0x10(%rax)
     711:	4c 39 d2             	cmp    %r10,%rdx
     714:	0f 85 e6 fe ff ff    	jne    600 <prepare_offsets+0xd0>
     71a:	c7 03 02 00 00 00    	movl   $0x2,(%rbx)
     720:	4c 89 e0             	mov    %r12,%rax
     723:	48 c1 e0 04          	shl    $0x4,%rax
     727:	4c 01 e0             	add    %r12,%rax
     72a:	48 c1 e0 07          	shl    $0x7,%rax
     72e:	48 01 c8             	add    %rcx,%rax
     731:	48 8b 94 24 38 03 00 	mov    0x338(%rsp),%rdx
     738:	00 
     739:	64 48 2b 14 25 28 00 	sub    %fs:0x28,%rdx
     740:	00 00 
     742:	75 1e                	jne    762 <prepare_offsets+0x232>
     744:	48 81 c4 48 03 00 00 	add    $0x348,%rsp
     74b:	5b                   	pop    %rbx
     74c:	5d                   	pop    %rbp
     74d:	41 5c                	pop    %r12
     74f:	41 5d                	pop    %r13
     751:	c3                   	ret    
     752:	8b 03                	mov    (%rbx),%eax
     754:	83 f8 02             	cmp    $0x2,%eax
     757:	75 f9                	jne    752 <prepare_offsets+0x222>
     759:	48 8d 0d 00 00 00 00 	lea    0x0(%rip),%rcx        # 760 <prepare_offsets+0x230>
     760:	eb be                	jmp    720 <prepare_offsets+0x1f0>
     762:	e8 00 00 00 00       	call   767 <prepare_offsets+0x237>
     767:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
     76e:	00 00 

0000000000000770 <layout_bytes>:
     770:	41 54                	push   %r12
     772:	49 89 d4             	mov    %rdx,%r12
     775:	66 0f ef c0          	pxor   %xmm0,%xmm0
     779:	55                   	push   %rbp
     77a:	53                   	push   %rbx
     77b:	48 89 cb             	mov    %rcx,%rbx
     77e:	b9 2a 00 00 00       	mov    $0x2a,%ecx
     783:	48 83 ec 50          	sub    $0x50,%rsp
     787:	48 8b 57 13          	mov    0x13(%rdi),%rdx
     78b:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
     792:	00 00 
     794:	48 89 44 24 48       	mov    %rax,0x48(%rsp)
     799:	31 c0                	xor    %eax,%eax
     79b:	0f b6 47 03          	movzbl 0x3(%rdi),%eax
     79f:	0f 29 44 24 10       	movaps %xmm0,0x10(%rsp)
     7a4:	48 89 e5             	mov    %rsp,%rbp
     7a7:	48 89 54 24 09       	mov    %rdx,0x9(%rsp)
     7ac:	8b 57 1b             	mov    0x1b(%rdi),%edx
     7af:	88 04 24             	mov    %al,(%rsp)
     7b2:	48 8b 47 08          	mov    0x8(%rdi),%rax
     7b6:	89 54 24 11          	mov    %edx,0x11(%rsp)
     7ba:	4c 89 e2             	mov    %r12,%rdx
     7bd:	48 89 44 24 01       	mov    %rax,0x1(%rsp)
     7c2:	0f b6 47 1f          	movzbl 0x1f(%rdi),%eax
     7c6:	48 8d 7c 24 16       	lea    0x16(%rsp),%rdi
     7cb:	0f 29 44 24 20       	movaps %xmm0,0x20(%rsp)
     7d0:	0f 29 44 24 30       	movaps %xmm0,0x30(%rsp)
     7d5:	88 44 24 15          	mov    %al,0x15(%rsp)
     7d9:	e8 00 00 00 00       	call   7de <layout_bytes+0x6e>
     7de:	42 c6 44 24 16 80    	movb   $0x80,0x16(%rsp,%r12,1)
     7e4:	4a 8d 04 e5 b0 02 00 	lea    0x2b0(,%r12,8),%rax
     7eb:	00 
     7ec:	8b 54 24 30          	mov    0x30(%rsp),%edx
     7f0:	48 0f c8             	bswap  %rax
     7f3:	66 48 0f 6e f0       	movq   %rax,%xmm6
     7f8:	8b 04 24             	mov    (%rsp),%eax
     7fb:	8b 7c 24 08          	mov    0x8(%rsp),%edi
     7ff:	0f ca                	bswap  %edx
     801:	66 0f 6e ca          	movd   %edx,%xmm1
     805:	8b 54 24 34          	mov    0x34(%rsp),%edx
     809:	44 8b 64 24 04       	mov    0x4(%rsp),%r12d
     80e:	0f c8                	bswap  %eax
     810:	66 0f 6e e8          	movd   %eax,%xmm5
     814:	8b 44 24 0c          	mov    0xc(%rsp),%eax
     818:	0f cf                	bswap  %edi
     81a:	0f ca                	bswap  %edx
     81c:	41 89 d3             	mov    %edx,%r11d
     81f:	66 0f 7e f2          	movd   %xmm6,%edx
     823:	66 0f 70 f6 e5       	pshufd $0xe5,%xmm6,%xmm6
     828:	0f c8                	bswap  %eax
     82a:	0f ca                	bswap  %edx
     82c:	66 0f 6e f8          	movd   %eax,%xmm7
     830:	66 0f 6e d2          	movd   %edx,%xmm2
     834:	66 0f 7e f2          	movd   %xmm6,%edx
     838:	66 0f 6e f7          	movd   %edi,%xmm6
     83c:	41 0f cc             	bswap  %r12d
     83f:	8b 44 24 10          	mov    0x10(%rsp),%eax
     843:	66 0f 62 f7          	punpckldq %xmm7,%xmm6
     847:	66 41 0f 6e fc       	movd   %r12d,%xmm7
     84c:	8b 74 24 18          	mov    0x18(%rsp),%esi
     850:	44 8b 54 24 1c       	mov    0x1c(%rsp),%r10d
     855:	66 0f 62 ef          	punpckldq %xmm7,%xmm5
     859:	44 8b 4c 24 14       	mov    0x14(%rsp),%r9d
     85e:	0f c8                	bswap  %eax
     860:	66 0f 6e e0          	movd   %eax,%xmm4
     864:	66 0f 6c ee          	punpcklqdq %xmm6,%xmm5
     868:	8b 44 24 20          	mov    0x20(%rsp),%eax
     86c:	0f ce                	bswap  %esi
     86e:	41 0f ca             	bswap  %r10d
     871:	0f 11 2b             	movups %xmm5,(%rbx)
     874:	66 41 0f 6e fa       	movd   %r10d,%xmm7
     879:	66 0f 6e ee          	movd   %esi,%xmm5
     87d:	0f ca                	bswap  %edx
     87f:	66 0f 62 ef          	punpckldq %xmm7,%xmm5
     883:	41 0f c9             	bswap  %r9d
     886:	66 41 0f 6e f9       	movd   %r9d,%xmm7
     88b:	44 8b 44 24 24       	mov    0x24(%rsp),%r8d
     890:	8b 4c 24 2c          	mov    0x2c(%rsp),%ecx
     894:	66 0f 62 e7          	punpckldq %xmm7,%xmm4
     898:	0f c8                	bswap  %eax
     89a:	66 0f 6e d8          	movd   %eax,%xmm3
     89e:	8b 44 24 28          	mov    0x28(%rsp),%eax
     8a2:	66 0f 6c e5          	punpcklqdq %xmm5,%xmm4
     8a6:	41 0f c8             	bswap  %r8d
     8a9:	66 41 0f 6e c0       	movd   %r8d,%xmm0
     8ae:	0f 11 63 10          	movups %xmm4,0x10(%rbx)
     8b2:	0f c9                	bswap  %ecx
     8b4:	66 0f 6e f9          	movd   %ecx,%xmm7
     8b8:	66 0f 62 d8          	punpckldq %xmm0,%xmm3
     8bc:	0f c8                	bswap  %eax
     8be:	66 0f 6e e0          	movd   %eax,%xmm4
     8c2:	66 0f ef c0          	pxor   %xmm0,%xmm0
     8c6:	66 0f 62 e7          	punpckldq %xmm7,%xmm4
     8ca:	0f 29 04 24          	movaps %xmm0,(%rsp)
     8ce:	66 0f 6c dc          	punpcklqdq %xmm4,%xmm3
     8d2:	0f 29 44 24 10       	movaps %xmm0,0x10(%rsp)
     8d7:	0f 11 5b 20          	movups %xmm3,0x20(%rbx)
     8db:	66 0f 6e da          	movd   %edx,%xmm3
     8df:	66 0f 62 d3          	punpckldq %xmm3,%xmm2
     8e3:	66 41 0f 6e db       	movd   %r11d,%xmm3
     8e8:	0f 29 44 24 20       	movaps %xmm0,0x20(%rsp)
     8ed:	66 0f 62 cb          	punpckldq %xmm3,%xmm1
     8f1:	0f 29 44 24 30       	movaps %xmm0,0x30(%rsp)
     8f6:	66 0f 6c ca          	punpcklqdq %xmm2,%xmm1
     8fa:	0f 11 4b 30          	movups %xmm1,0x30(%rbx)
     8fe:	48 8b 44 24 48       	mov    0x48(%rsp),%rax
     903:	64 48 2b 04 25 28 00 	sub    %fs:0x28,%rax
     90a:	00 00 
     90c:	75 09                	jne    917 <layout_bytes+0x1a7>
     90e:	48 83 c4 50          	add    $0x50,%rsp
     912:	5b                   	pop    %rbx
     913:	5d                   	pop    %rbp
     914:	41 5c                	pop    %r12
     916:	c3                   	ret    
     917:	e8 00 00 00 00       	call   91c <layout_bytes+0x1ac>
     91c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000000920 <rounds8>:
     920:	55                   	push   %rbp
     921:	49 89 f2             	mov    %rsi,%r10
     924:	49 89 c9             	mov    %rcx,%r9
     927:	31 f6                	xor    %esi,%esi
     929:	31 c9                	xor    %ecx,%ecx
     92b:	48 89 e5             	mov    %rsp,%rbp
     92e:	53                   	push   %rbx
     92f:	48 83 e4 e0          	and    $0xffffffffffffffe0,%rsp
     933:	48 81 ec 40 03 00 00 	sub    $0x340,%rsp
     93a:	c4 e2 7d 58 07       	vpbroadcastd (%rdi),%ymm0
     93f:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
     946:	00 00 
     948:	48 89 84 24 38 03 00 	mov    %rax,0x338(%rsp)
     94f:	00 
     950:	31 c0                	xor    %eax,%eax
     952:	c5 fd 6f e8          	vmovdqa %ymm0,%ymm5
     956:	c5 fd 7f 04 24       	vmovdqa %ymm0,(%rsp)
     95b:	c4 e2 7d 58 47 04    	vpbroadcastd 0x4(%rdi),%ymm0
     961:	c5 7d 6f c8          	vmovdqa %ymm0,%ymm9
     965:	c5 fd 7f 44 24 20    	vmovdqa %ymm0,0x20(%rsp)
     96b:	c4 e2 7d 58 47 08    	vpbroadcastd 0x8(%rdi),%ymm0
     971:	c5 7d 6f c0          	vmovdqa %ymm0,%ymm8
     975:	c5 fd 7f 44 24 40    	vmovdqa %ymm0,0x40(%rsp)
     97b:	c4 e2 7d 58 47 0c    	vpbroadcastd 0xc(%rdi),%ymm0
     981:	c5 7d 6f e0          	vmovdqa %ymm0,%ymm12
     985:	c5 fd 7f 44 24 60    	vmovdqa %ymm0,0x60(%rsp)
     98b:	c4 e2 7d 58 47 10    	vpbroadcastd 0x10(%rdi),%ymm0
     991:	c5 fd 7f 84 24 80 00 	vmovdqa %ymm0,0x80(%rsp)
     998:	00 00 
     99a:	c5 fd 6f f0          	vmovdqa %ymm0,%ymm6
     99e:	c4 e2 7d 58 47 14    	vpbroadcastd 0x14(%rdi),%ymm0
     9a4:	c5 fd 7f 84 24 a0 00 	vmovdqa %ymm0,0xa0(%rsp)
     9ab:	00 00 
     9ad:	c5 7d 6f d0          	vmovdqa %ymm0,%ymm10
     9b1:	c4 e2 7d 58 47 18    	vpbroadcastd 0x18(%rdi),%ymm0
     9b7:	c5 fd 7f 84 24 c0 00 	vmovdqa %ymm0,0xc0(%rsp)
     9be:	00 00 
     9c0:	c5 fd 6f f8          	vmovdqa %ymm0,%ymm7
     9c4:	c4 e2 7d 58 47 1c    	vpbroadcastd 0x1c(%rdi),%ymm0
     9ca:	c5 fd 7f 84 24 e0 00 	vmovdqa %ymm0,0xe0(%rsp)
     9d1:	00 00 
     9d3:	c5 7d 6f d8          	vmovdqa %ymm0,%ymm11
     9d7:	e9 24 01 00 00       	jmp    b00 <rounds8+0x1e0>
     9dc:	0f 1f 40 00          	nopl   0x0(%rax)
     9e0:	c4 e2 7d 58 24 32    	vpbroadcastd (%rdx,%rsi,1),%ymm4
     9e6:	c4 c1 5d ef 24 f1    	vpxor  (%r9,%rsi,8),%ymm4,%ymm4
     9ec:	c4 62 7d 58 6c 32 10 	vpbroadcastd 0x10(%rdx,%rsi,1),%ymm13
     9f3:	c4 41 15 ef ac f1 80 	vpxor  0x80(%r9,%rsi,8),%ymm13,%ymm13
     9fa:	00 00 00 
     9fd:	c5 fd 6f c4          	vmovdqa %ymm4,%ymm0
     a01:	c5 f5 72 d5 14       	vpsrld $0x14,%ymm5,%ymm1
     a06:	c5 e5 72 f5 0c       	vpslld $0xc,%ymm5,%ymm3
     a0b:	83 f9 10             	cmp    $0x10,%ecx
     a0e:	19 c0                	sbb    %eax,%eax
     a10:	c5 e5 eb d9          	vpor   %ymm1,%ymm3,%ymm3
     a14:	25 8f a7 44 ff       	and    $0xff44a78f,%eax
     a19:	c5 cd fe cb          	vpaddd %ymm3,%ymm6,%ymm1
     a1d:	05 8a 9d 87 7a       	add    $0x7a879d8a,%eax
     a22:	d3 c0                	rol    %cl,%eax
     a24:	c5 f9 6e d0          	vmovd  %eax,%xmm2
     a28:	c4 e2 7d 58 d2       	vpbroadcastd %xmm2,%ymm2
     a2d:	c5 f5 fe ca          	vpaddd %ymm2,%ymm1,%ymm1
     a31:	c5 ed 72 d1 19       	vpsrld $0x19,%ymm1,%ymm2
     a36:	c5 f5 72 f1 07       	vpslld $0x7,%ymm1,%ymm1
     a3b:	c5 f5 eb ca          	vpor   %ymm2,%ymm1,%ymm1
     a3f:	83 f9 0f             	cmp    $0xf,%ecx
     a42:	0f 86 e0 00 00 00    	jbe    b28 <rounds8+0x208>
     a48:	c4 41 55 eb f1       	vpor   %ymm9,%ymm5,%ymm14
     a4d:	c4 c1 55 db d1       	vpand  %ymm9,%ymm5,%ymm2
     a52:	c5 4d df ff          	vpandn %ymm7,%ymm6,%ymm15
     a56:	c4 41 0d db f0       	vpand  %ymm8,%ymm14,%ymm14
     a5b:	c5 0d eb f2          	vpor   %ymm2,%ymm14,%ymm14
     a5f:	c4 c1 4d db d2       	vpand  %ymm10,%ymm6,%ymm2
     a64:	c4 c1 6d eb d7       	vpor   %ymm15,%ymm2,%ymm2
     a69:	c5 e5 ef d9          	vpxor  %ymm1,%ymm3,%ymm3
     a6d:	c4 c1 5d ef e5       	vpxor  %ymm13,%ymm4,%ymm4
     a72:	c5 ed fe d1          	vpaddd %ymm1,%ymm2,%ymm2
     a76:	83 c1 01             	add    $0x1,%ecx
     a79:	c4 c1 5d fe e4       	vpaddd %ymm12,%ymm4,%ymm4
     a7e:	c4 c1 65 fe de       	vpaddd %ymm14,%ymm3,%ymm3
     a83:	c4 41 7d 6f e0       	vmovdqa %ymm8,%ymm12
     a88:	48 83 c6 04          	add    $0x4,%rsi
     a8c:	c4 c1 75 72 d1 17    	vpsrld $0x17,%ymm9,%ymm1
     a92:	c5 a5 fe c0          	vpaddd %ymm0,%ymm11,%ymm0
     a96:	c5 dd fe e3          	vpaddd %ymm3,%ymm4,%ymm4
     a9a:	c4 c1 65 72 f1 09    	vpslld $0x9,%ymm9,%ymm3
     aa0:	c5 fd fe c2          	vpaddd %ymm2,%ymm0,%ymm0
     aa4:	c4 c1 6d 72 f2 13    	vpslld $0x13,%ymm10,%ymm2
     aaa:	c5 a5 72 d0 17       	vpsrld $0x17,%ymm0,%ymm11
     aaf:	c5 e5 eb d9          	vpor   %ymm1,%ymm3,%ymm3
     ab3:	c4 c1 75 72 d2 0d    	vpsrld $0xd,%ymm10,%ymm1
     ab9:	c5 b5 72 f0 11       	vpslld $0x11,%ymm0,%ymm9
     abe:	c5 ad 72 d0 0f       	vpsrld $0xf,%ymm0,%ymm10
     ac3:	c5 ed eb d1          	vpor   %ymm1,%ymm2,%ymm2
     ac7:	c5 f5 72 f0 09       	vpslld $0x9,%ymm0,%ymm1
     acc:	c4 41 35 eb ca       	vpor   %ymm10,%ymm9,%ymm9
     ad1:	c5 7d 6f d6          	vmovdqa %ymm6,%ymm10
     ad5:	c4 c1 75 eb cb       	vpor   %ymm11,%ymm1,%ymm1
     ada:	c5 7d 6f df          	vmovdqa %ymm7,%ymm11
     ade:	c4 c1 75 ef c9       	vpxor  %ymm9,%ymm1,%ymm1
     ae3:	c5 7d 6f cd          	vmovdqa %ymm5,%ymm9
     ae7:	c5 f5 ef c8          	vpxor  %ymm0,%ymm1,%ymm1
     aeb:	83 f9 40             	cmp    $0x40,%ecx
     aee:	74 50                	je     b40 <rounds8+0x220>
     af0:	c5 fd 6f fa          	vmovdqa %ymm2,%ymm7
     af4:	c5 7d 6f c3          	vmovdqa %ymm3,%ymm8
     af8:	c5 fd 6f f1          	vmovdqa %ymm1,%ymm6
     afc:	c5 fd 6f ec          	vmovdqa %ymm4,%ymm5
     b00:	48 85 d2             	test   %rdx,%rdx
     b03:	0f 85 d7 fe ff ff    	jne    9e0 <rounds8+0xc0>
     b09:	c4 41 7e 6f ac f2 80 	vmovdqu 0x80(%r10,%rsi,8),%ymm13
     b10:	00 00 00 
     b13:	c4 c1 7e 6f 04 f2    	vmovdqu (%r10,%rsi,8),%ymm0
     b19:	c5 fd 6f e0          	vmovdqa %ymm0,%ymm4
     b1d:	e9 df fe ff ff       	jmp    a01 <rounds8+0xe1>
     b22:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
     b28:	c5 3d ef f5          	vpxor  %ymm5,%ymm8,%ymm14
     b2c:	c4 c1 4d ef d2       	vpxor  %ymm10,%ymm6,%ymm2
     b31:	c4 41 0d ef f1       	vpxor  %ymm9,%ymm14,%ymm14
     b36:	c5 ed ef d7          	vpxor  %ymm7,%ymm2,%ymm2
     b3a:	e9 2a ff ff ff       	jmp    a69 <rounds8+0x149>
     b3f:	90                   	nop
     b40:	c5 7d 7f 84 24 60 01 	vmovdqa %ymm8,0x160(%rsp)
     b47:	00 00 
     b49:	48 89 e6             	mov    %rsp,%rsi
     b4c:	4c 89 c0             	mov    %r8,%rax
     b4f:	4c 8d 84 24 00 01 00 	lea    0x100(%rsp),%r8
     b56:	00 
     b57:	c5 fd 7f 9c 24 40 01 	vmovdqa %ymm3,0x140(%rsp)
     b5e:	00 00 
     b60:	48 89 f1             	mov    %rsi,%rcx
     b63:	c5 fd 7f ac 24 20 01 	vmovdqa %ymm5,0x120(%rsp)
     b6a:	00 00 
     b6c:	c5 fd 7f a4 24 00 01 	vmovdqa %ymm4,0x100(%rsp)
     b73:	00 00 
     b75:	c5 fd 7f bc 24 e0 01 	vmovdqa %ymm7,0x1e0(%rsp)
     b7c:	00 00 
     b7e:	c5 fd 7f 94 24 c0 01 	vmovdqa %ymm2,0x1c0(%rsp)
     b85:	00 00 
     b87:	c5 fd 7f b4 24 a0 01 	vmovdqa %ymm6,0x1a0(%rsp)
     b8e:	00 00 
     b90:	c5 fd 7f 8c 24 80 01 	vmovdqa %ymm1,0x180(%rsp)
     b97:	00 00 
     b99:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
     ba0:	c5 fd 6f 39          	vmovdqa (%rcx),%ymm7
     ba4:	c5 c5 ef 81 00 01 00 	vpxor  0x100(%rcx),%ymm7,%ymm0
     bab:	00 
     bac:	48 83 c1 20          	add    $0x20,%rcx
     bb0:	48 83 c0 04          	add    $0x4,%rax
     bb4:	c5 f9 7e c7          	vmovd  %xmm0,%edi
     bb8:	c5 f9 7e c2          	vmovd  %xmm0,%edx
     bbc:	c1 ef 18             	shr    $0x18,%edi
     bbf:	88 70 fe             	mov    %dh,-0x2(%rax)
     bc2:	40 88 78 fc          	mov    %dil,-0x4(%rax)
     bc6:	c5 f9 7e c7          	vmovd  %xmm0,%edi
     bca:	88 50 ff             	mov    %dl,-0x1(%rax)
     bcd:	c1 ef 10             	shr    $0x10,%edi
     bd0:	c4 e3 79 16 c2 01    	vpextrd $0x1,%xmm0,%edx
     bd6:	40 88 78 fd          	mov    %dil,-0x3(%rax)
     bda:	89 d7                	mov    %edx,%edi
     bdc:	c1 ef 18             	shr    $0x18,%edi
     bdf:	88 70 1e             	mov    %dh,0x1e(%rax)
     be2:	40 88 78 1c          	mov    %dil,0x1c(%rax)
     be6:	89 d7                	mov    %edx,%edi
     be8:	88 50 1f             	mov    %dl,0x1f(%rax)
     beb:	c1 ef 10             	shr    $0x10,%edi
     bee:	c4 e3 79 16 c2 02    	vpextrd $0x2,%xmm0,%edx
     bf4:	40 88 78 1d          	mov    %dil,0x1d(%rax)
     bf8:	89 d7                	mov    %edx,%edi
     bfa:	c1 ef 18             	shr    $0x18,%edi
     bfd:	88 70 3e             	mov    %dh,0x3e(%rax)
     c00:	40 88 78 3c          	mov    %dil,0x3c(%rax)
     c04:	89 d7                	mov    %edx,%edi
     c06:	88 50 3f             	mov    %dl,0x3f(%rax)
     c09:	c1 ef 10             	shr    $0x10,%edi
     c0c:	c4 e3 79 16 c2 03    	vpextrd $0x3,%xmm0,%edx
     c12:	c4 e3 7d 39 c0 01    	vextracti128 $0x1,%ymm0,%xmm0
     c18:	40 88 78 3d          	mov    %dil,0x3d(%rax)
     c1c:	89 d7                	mov    %edx,%edi
     c1e:	c1 ef 18             	shr    $0x18,%edi
     c21:	88 70 5e             	mov    %dh,0x5e(%rax)
     c24:	40 88 78 5c          	mov    %dil,0x5c(%rax)
     c28:	89 d7                	mov    %edx,%edi
     c2a:	c1 ef 10             	shr    $0x10,%edi
     c2d:	88 50 5f             	mov    %dl,0x5f(%rax)
     c30:	c5 f9 7e c2          	vmovd  %xmm0,%edx
     c34:	40 88 78 5d          	mov    %dil,0x5d(%rax)
     c38:	c5 f9 7e c7          	vmovd  %xmm0,%edi
     c3c:	c1 ef 18             	shr    $0x18,%edi
     c3f:	88 70 7e             	mov    %dh,0x7e(%rax)
     c42:	40 88 78 7c          	mov    %dil,0x7c(%rax)
     c46:	c5 f9 7e c7          	vmovd  %xmm0,%edi
     c4a:	88 50 7f             	mov    %dl,0x7f(%rax)
     c4d:	c1 ef 10             	shr    $0x10,%edi
     c50:	c4 e3 79 16 c2 01    	vpextrd $0x1,%xmm0,%edx
     c56:	40 88 78 7d          	mov    %dil,0x7d(%rax)
     c5a:	89 d7                	mov    %edx,%edi
     c5c:	c1 ef 18             	shr    $0x18,%edi
     c5f:	88 b0 9e 00 00 00    	mov    %dh,0x9e(%rax)
     c65:	40 88 b8 9c 00 00 00 	mov    %dil,0x9c(%rax)
     c6c:	89 d7                	mov    %edx,%edi
     c6e:	88 90 9f 00 00 00    	mov    %dl,0x9f(%rax)
     c74:	c1 ef 10             	shr    $0x10,%edi
     c77:	c4 e3 79 16 c2 02    	vpextrd $0x2,%xmm0,%edx
     c7d:	40 88 b8 9d 00 00 00 	mov    %dil,0x9d(%rax)
     c84:	89 d7                	mov    %edx,%edi
     c86:	c1 ef 18             	shr    $0x18,%edi
     c89:	88 b0 be 00 00 00    	mov    %dh,0xbe(%rax)
     c8f:	40 88 b8 bc 00 00 00 	mov    %dil,0xbc(%rax)
     c96:	89 d7                	mov    %edx,%edi
     c98:	88 90 bf 00 00 00    	mov    %dl,0xbf(%rax)
     c9e:	c1 ef 10             	shr    $0x10,%edi
     ca1:	c4 e3 79 16 c2 03    	vpextrd $0x3,%xmm0,%edx
     ca7:	40 88 b8 bd 00 00 00 	mov    %dil,0xbd(%rax)
     cae:	89 d7                	mov    %edx,%edi
     cb0:	c1 ef 18             	shr    $0x18,%edi
     cb3:	40 88 b8 dc 00 00 00 	mov    %dil,0xdc(%rax)
     cba:	89 d7                	mov    %edx,%edi
     cbc:	c1 ef 10             	shr    $0x10,%edi
     cbf:	40 88 b8 dd 00 00 00 	mov    %dil,0xdd(%rax)
     cc6:	88 b0 de 00 00 00    	mov    %dh,0xde(%rax)
     ccc:	88 90 df 00 00 00    	mov    %dl,0xdf(%rax)
     cd2:	4c 39 c1             	cmp    %r8,%rcx
     cd5:	0f 85 c5 fe ff ff    	jne    ba0 <rounds8+0x280>
     cdb:	31 c0                	xor    %eax,%eax
     cdd:	48 89 f7             	mov    %rsi,%rdi
     ce0:	b9 64 00 00 00       	mov    $0x64,%ecx
     ce5:	f3 48 ab             	rep stos %rax,%es:(%rdi)
     ce8:	48 8b 84 24 38 03 00 	mov    0x338(%rsp),%rax
     cef:	00 
     cf0:	64 48 2b 04 25 28 00 	sub    %fs:0x28,%rax
     cf7:	00 00 
     cf9:	75 09                	jne    d04 <rounds8+0x3e4>
     cfb:	c5 f8 77             	vzeroupper 
     cfe:	48 8b 5d f8          	mov    -0x8(%rbp),%rbx
     d02:	c9                   	leave  
     d03:	c3                   	ret    
     d04:	c5 f8 77             	vzeroupper 
     d07:	e8 00 00 00 00       	call   d0c <rounds8+0x3ec>
     d0c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000000d10 <rounds8.constprop.0>:
     d10:	55                   	push   %rbp
     d11:	31 c9                	xor    %ecx,%ecx
     d13:	48 89 e5             	mov    %rsp,%rbp
     d16:	53                   	push   %rbx
     d17:	48 83 e4 e0          	and    $0xffffffffffffffe0,%rsp
     d1b:	48 81 ec 40 03 00 00 	sub    $0x340,%rsp
     d22:	c4 e2 7d 58 07       	vpbroadcastd (%rdi),%ymm0
     d27:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
     d2e:	00 00 
     d30:	48 89 84 24 38 03 00 	mov    %rax,0x338(%rsp)
     d37:	00 
     d38:	31 c0                	xor    %eax,%eax
     d3a:	c5 fd 6f e0          	vmovdqa %ymm0,%ymm4
     d3e:	c5 fd 7f 04 24       	vmovdqa %ymm0,(%rsp)
     d43:	c4 e2 7d 58 47 04    	vpbroadcastd 0x4(%rdi),%ymm0
     d49:	c5 7d 6f c0          	vmovdqa %ymm0,%ymm8
     d4d:	c5 fd 7f 44 24 20    	vmovdqa %ymm0,0x20(%rsp)
     d53:	c4 e2 7d 58 47 08    	vpbroadcastd 0x8(%rdi),%ymm0
     d59:	c5 fd 6f f8          	vmovdqa %ymm0,%ymm7
     d5d:	c5 fd 7f 44 24 40    	vmovdqa %ymm0,0x40(%rsp)
     d63:	c4 e2 7d 58 47 0c    	vpbroadcastd 0xc(%rdi),%ymm0
     d69:	c5 7d 6f d8          	vmovdqa %ymm0,%ymm11
     d6d:	c5 fd 7f 44 24 60    	vmovdqa %ymm0,0x60(%rsp)
     d73:	c4 e2 7d 58 47 10    	vpbroadcastd 0x10(%rdi),%ymm0
     d79:	c5 fd 7f 84 24 80 00 	vmovdqa %ymm0,0x80(%rsp)
     d80:	00 00 
     d82:	c5 fd 6f e8          	vmovdqa %ymm0,%ymm5
     d86:	c4 e2 7d 58 47 14    	vpbroadcastd 0x14(%rdi),%ymm0
     d8c:	c5 fd 7f 84 24 a0 00 	vmovdqa %ymm0,0xa0(%rsp)
     d93:	00 00 
     d95:	c5 7d 6f c8          	vmovdqa %ymm0,%ymm9
     d99:	c4 e2 7d 58 47 18    	vpbroadcastd 0x18(%rdi),%ymm0
     d9f:	c5 fd 7f 84 24 c0 00 	vmovdqa %ymm0,0xc0(%rsp)
     da6:	00 00 
     da8:	c5 fd 6f f0          	vmovdqa %ymm0,%ymm6
     dac:	c4 e2 7d 58 47 1c    	vpbroadcastd 0x1c(%rdi),%ymm0
     db2:	c5 fd 7f 84 24 e0 00 	vmovdqa %ymm0,0xe0(%rsp)
     db9:	00 00 
     dbb:	c5 7d 6f d0          	vmovdqa %ymm0,%ymm10
     dbf:	e9 b9 00 00 00       	jmp    e7d <rounds8.constprop.0+0x16d>
     dc4:	0f 1f 40 00          	nopl   0x0(%rax)
     dc8:	c5 3d eb f4          	vpor   %ymm4,%ymm8,%ymm14
     dcc:	c5 bd db d4          	vpand  %ymm4,%ymm8,%ymm2
     dd0:	c5 35 db e5          	vpand  %ymm5,%ymm9,%ymm12
     dd4:	c5 0d db f7          	vpand  %ymm7,%ymm14,%ymm14
     dd8:	c5 0d eb f2          	vpor   %ymm2,%ymm14,%ymm14
     ddc:	c5 d5 df d6          	vpandn %ymm6,%ymm5,%ymm2
     de0:	c5 1d eb e2          	vpor   %ymm2,%ymm12,%ymm12
     de4:	c5 e5 ef d8          	vpxor  %ymm0,%ymm3,%ymm3
     de8:	c5 95 ef d1          	vpxor  %ymm1,%ymm13,%ymm2
     dec:	c5 ad fe c0          	vpaddd %ymm0,%ymm10,%ymm0
     df0:	83 c1 01             	add    $0x1,%ecx
     df3:	c4 c1 65 fe db       	vpaddd %ymm11,%ymm3,%ymm3
     df8:	c4 c1 6d fe d6       	vpaddd %ymm14,%ymm2,%ymm2
     dfd:	c5 7d 6f df          	vmovdqa %ymm7,%ymm11
     e01:	48 83 c6 20          	add    $0x20,%rsi
     e05:	c4 41 1d fe e5       	vpaddd %ymm13,%ymm12,%ymm12
     e0a:	c5 e5 fe ca          	vpaddd %ymm2,%ymm3,%ymm1
     e0e:	c4 c1 65 72 d1 0d    	vpsrld $0xd,%ymm9,%ymm3
     e14:	c4 c1 7d fe c4       	vpaddd %ymm12,%ymm0,%ymm0
     e19:	c4 c1 35 72 f1 13    	vpslld $0x13,%ymm9,%ymm9
     e1f:	c4 c1 1d 72 d0 17    	vpsrld $0x17,%ymm8,%ymm12
     e25:	c4 c1 3d 72 f0 09    	vpslld $0x9,%ymm8,%ymm8
     e2b:	c4 c1 65 eb d9       	vpor   %ymm9,%ymm3,%ymm3
     e30:	c5 ad 72 f0 09       	vpslld $0x9,%ymm0,%ymm10
     e35:	c5 b5 72 f0 11       	vpslld $0x11,%ymm0,%ymm9
     e3a:	c4 41 1d eb e0       	vpor   %ymm8,%ymm12,%ymm12
     e3f:	c5 ed 72 d0 17       	vpsrld $0x17,%ymm0,%ymm2
     e44:	c5 bd 72 d0 0f       	vpsrld $0xf,%ymm0,%ymm8
     e49:	c4 41 3d eb c1       	vpor   %ymm9,%ymm8,%ymm8
     e4e:	c4 c1 6d eb d2       	vpor   %ymm10,%ymm2,%ymm2
     e53:	c5 7d 6f cd          	vmovdqa %ymm5,%ymm9
     e57:	c4 c1 6d ef d0       	vpxor  %ymm8,%ymm2,%ymm2
     e5c:	c5 7d 6f d6          	vmovdqa %ymm6,%ymm10
     e60:	c5 7d 6f c4          	vmovdqa %ymm4,%ymm8
     e64:	c5 ed ef d0          	vpxor  %ymm0,%ymm2,%ymm2
     e68:	83 f9 40             	cmp    $0x40,%ecx
     e6b:	74 7b                	je     ee8 <rounds8.constprop.0+0x1d8>
     e6d:	c5 fd 6f f3          	vmovdqa %ymm3,%ymm6
     e71:	c5 7d 7f e7          	vmovdqa %ymm12,%ymm7
     e75:	c5 fd 6f ea          	vmovdqa %ymm2,%ymm5
     e79:	c5 fd 6f e1          	vmovdqa %ymm1,%ymm4
     e7d:	83 f9 10             	cmp    $0x10,%ecx
     e80:	c5 ed 72 f4 0c       	vpslld $0xc,%ymm4,%ymm2
     e85:	c5 fe 6f 06          	vmovdqu (%rsi),%ymm0
     e89:	c5 fe 6f 9e 80 00 00 	vmovdqu 0x80(%rsi),%ymm3
     e90:	00 
     e91:	19 c0                	sbb    %eax,%eax
     e93:	c5 f5 72 d4 14       	vpsrld $0x14,%ymm4,%ymm1
     e98:	25 8f a7 44 ff       	and    $0xff44a78f,%eax
     e9d:	c5 f5 eb ca          	vpor   %ymm2,%ymm1,%ymm1
     ea1:	05 8a 9d 87 7a       	add    $0x7a879d8a,%eax
     ea6:	c5 55 fe e1          	vpaddd %ymm1,%ymm5,%ymm12
     eaa:	d3 c0                	rol    %cl,%eax
     eac:	c5 f9 6e d0          	vmovd  %eax,%xmm2
     eb0:	c4 e2 7d 58 d2       	vpbroadcastd %xmm2,%ymm2
     eb5:	c5 9d fe d2          	vpaddd %ymm2,%ymm12,%ymm2
     eb9:	c5 95 72 d2 19       	vpsrld $0x19,%ymm2,%ymm13
     ebe:	c5 ed 72 f2 07       	vpslld $0x7,%ymm2,%ymm2
     ec3:	c5 15 eb ea          	vpor   %ymm2,%ymm13,%ymm13
     ec7:	83 f9 0f             	cmp    $0xf,%ecx
     eca:	0f 87 f8 fe ff ff    	ja     dc8 <rounds8.constprop.0+0xb8>
     ed0:	c5 3d ef f4          	vpxor  %ymm4,%ymm8,%ymm14
     ed4:	c5 35 ef e5          	vpxor  %ymm5,%ymm9,%ymm12
     ed8:	c5 0d ef f7          	vpxor  %ymm7,%ymm14,%ymm14
     edc:	c5 1d ef e6          	vpxor  %ymm6,%ymm12,%ymm12
     ee0:	e9 ff fe ff ff       	jmp    de4 <rounds8.constprop.0+0xd4>
     ee5:	0f 1f 00             	nopl   (%rax)
     ee8:	c5 fd 7f bc 24 60 01 	vmovdqa %ymm7,0x160(%rsp)
     eef:	00 00 
     ef1:	48 89 e6             	mov    %rsp,%rsi
     ef4:	4c 89 c0             	mov    %r8,%rax
     ef7:	4c 8d 84 24 00 01 00 	lea    0x100(%rsp),%r8
     efe:	00 
     eff:	c5 7d 7f a4 24 40 01 	vmovdqa %ymm12,0x140(%rsp)
     f06:	00 00 
     f08:	48 89 f1             	mov    %rsi,%rcx
     f0b:	c5 fd 7f a4 24 20 01 	vmovdqa %ymm4,0x120(%rsp)
     f12:	00 00 
     f14:	c5 fd 7f 8c 24 00 01 	vmovdqa %ymm1,0x100(%rsp)
     f1b:	00 00 
     f1d:	c5 fd 7f b4 24 e0 01 	vmovdqa %ymm6,0x1e0(%rsp)
     f24:	00 00 
     f26:	c5 fd 7f 9c 24 c0 01 	vmovdqa %ymm3,0x1c0(%rsp)
     f2d:	00 00 
     f2f:	c5 fd 7f ac 24 a0 01 	vmovdqa %ymm5,0x1a0(%rsp)
     f36:	00 00 
     f38:	c5 fd 7f 94 24 80 01 	vmovdqa %ymm2,0x180(%rsp)
     f3f:	00 00 
     f41:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
     f48:	c5 fd 6f 31          	vmovdqa (%rcx),%ymm6
     f4c:	c5 cd ef 81 00 01 00 	vpxor  0x100(%rcx),%ymm6,%ymm0
     f53:	00 
     f54:	48 83 c1 20          	add    $0x20,%rcx
     f58:	48 83 c0 04          	add    $0x4,%rax
     f5c:	c5 f9 7e c7          	vmovd  %xmm0,%edi
     f60:	c5 f9 7e c2          	vmovd  %xmm0,%edx
     f64:	c1 ef 18             	shr    $0x18,%edi
     f67:	88 70 fe             	mov    %dh,-0x2(%rax)
     f6a:	40 88 78 fc          	mov    %dil,-0x4(%rax)
     f6e:	c5 f9 7e c7          	vmovd  %xmm0,%edi
     f72:	88 50 ff             	mov    %dl,-0x1(%rax)
     f75:	c1 ef 10             	shr    $0x10,%edi
     f78:	c4 e3 79 16 c2 01    	vpextrd $0x1,%xmm0,%edx
     f7e:	40 88 78 fd          	mov    %dil,-0x3(%rax)
     f82:	89 d7                	mov    %edx,%edi
     f84:	c1 ef 18             	shr    $0x18,%edi
     f87:	88 70 1e             	mov    %dh,0x1e(%rax)
     f8a:	40 88 78 1c          	mov    %dil,0x1c(%rax)
     f8e:	89 d7                	mov    %edx,%edi
     f90:	88 50 1f             	mov    %dl,0x1f(%rax)
     f93:	c1 ef 10             	shr    $0x10,%edi
     f96:	c4 e3 79 16 c2 02    	vpextrd $0x2,%xmm0,%edx
     f9c:	40 88 78 1d          	mov    %dil,0x1d(%rax)
     fa0:	89 d7                	mov    %edx,%edi
     fa2:	c1 ef 18             	shr    $0x18,%edi
     fa5:	88 70 3e             	mov    %dh,0x3e(%rax)
     fa8:	40 88 78 3c          	mov    %dil,0x3c(%rax)
     fac:	89 d7                	mov    %edx,%edi
     fae:	88 50 3f             	mov    %dl,0x3f(%rax)
     fb1:	c1 ef 10             	shr    $0x10,%edi
     fb4:	c4 e3 79 16 c2 03    	vpextrd $0x3,%xmm0,%edx
     fba:	c4 e3 7d 39 c0 01    	vextracti128 $0x1,%ymm0,%xmm0
     fc0:	40 88 78 3d          	mov    %dil,0x3d(%rax)
     fc4:	89 d7                	mov    %edx,%edi
     fc6:	c1 ef 18             	shr    $0x18,%edi
     fc9:	88 70 5e             	mov    %dh,0x5e(%rax)
     fcc:	40 88 78 5c          	mov    %dil,0x5c(%rax)
     fd0:	89 d7                	mov    %edx,%edi
     fd2:	c1 ef 10             	shr    $0x10,%edi
     fd5:	88 50 5f             	mov    %dl,0x5f(%rax)
     fd8:	c5 f9 7e c2          	vmovd  %xmm0,%edx
     fdc:	40 88 78 5d          	mov    %dil,0x5d(%rax)
     fe0:	c5 f9 7e c7          	vmovd  %xmm0,%edi
     fe4:	c1 ef 18             	shr    $0x18,%edi
     fe7:	88 70 7e             	mov    %dh,0x7e(%rax)
     fea:	40 88 78 7c          	mov    %dil,0x7c(%rax)
     fee:	c5 f9 7e c7          	vmovd  %xmm0,%edi
     ff2:	88 50 7f             	mov    %dl,0x7f(%rax)
     ff5:	c1 ef 10             	shr    $0x10,%edi
     ff8:	c4 e3 79 16 c2 01    	vpextrd $0x1,%xmm0,%edx
     ffe:	40 88 78 7d          	mov    %dil,0x7d(%rax)
    1002:	89 d7                	mov    %edx,%edi
    1004:	c1 ef 18             	shr    $0x18,%edi
    1007:	88 b0 9e 00 00 00    	mov    %dh,0x9e(%rax)
    100d:	40 88 b8 9c 00 00 00 	mov    %dil,0x9c(%rax)
    1014:	89 d7                	mov    %edx,%edi
    1016:	88 90 9f 00 00 00    	mov    %dl,0x9f(%rax)
    101c:	c1 ef 10             	shr    $0x10,%edi
    101f:	c4 e3 79 16 c2 02    	vpextrd $0x2,%xmm0,%edx
    1025:	40 88 b8 9d 00 00 00 	mov    %dil,0x9d(%rax)
    102c:	89 d7                	mov    %edx,%edi
    102e:	c1 ef 18             	shr    $0x18,%edi
    1031:	88 b0 be 00 00 00    	mov    %dh,0xbe(%rax)
    1037:	40 88 b8 bc 00 00 00 	mov    %dil,0xbc(%rax)
    103e:	89 d7                	mov    %edx,%edi
    1040:	88 90 bf 00 00 00    	mov    %dl,0xbf(%rax)
    1046:	c1 ef 10             	shr    $0x10,%edi
    1049:	c4 e3 79 16 c2 03    	vpextrd $0x3,%xmm0,%edx
    104f:	40 88 b8 bd 00 00 00 	mov    %dil,0xbd(%rax)
    1056:	89 d7                	mov    %edx,%edi
    1058:	c1 ef 18             	shr    $0x18,%edi
    105b:	40 88 b8 dc 00 00 00 	mov    %dil,0xdc(%rax)
    1062:	89 d7                	mov    %edx,%edi
    1064:	c1 ef 10             	shr    $0x10,%edi
    1067:	40 88 b8 dd 00 00 00 	mov    %dil,0xdd(%rax)
    106e:	88 b0 de 00 00 00    	mov    %dh,0xde(%rax)
    1074:	88 90 df 00 00 00    	mov    %dl,0xdf(%rax)
    107a:	49 39 c8             	cmp    %rcx,%r8
    107d:	0f 85 c5 fe ff ff    	jne    f48 <rounds8.constprop.0+0x238>
    1083:	31 c0                	xor    %eax,%eax
    1085:	48 89 f7             	mov    %rsi,%rdi
    1088:	b9 64 00 00 00       	mov    $0x64,%ecx
    108d:	f3 48 ab             	rep stos %rax,%es:(%rdi)
    1090:	48 8b 84 24 38 03 00 	mov    0x338(%rsp),%rax
    1097:	00 
    1098:	64 48 2b 04 25 28 00 	sub    %fs:0x28,%rax
    109f:	00 00 
    10a1:	75 09                	jne    10ac <rounds8.constprop.0+0x39c>
    10a3:	c5 f8 77             	vzeroupper 
    10a6:	48 8b 5d f8          	mov    -0x8(%rbp),%rbx
    10aa:	c9                   	leave  
    10ab:	c3                   	ret    
    10ac:	c5 f8 77             	vzeroupper 
    10af:	e8 00 00 00 00       	call   10b4 <rounds8.constprop.0+0x3a4>
    10b4:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
    10bb:	00 00 00 00 
    10bf:	90                   	nop

00000000000010c0 <a15_sm3i_layout_words>:
    10c0:	f3 0f 1e fa          	endbr64 
    10c4:	48 85 ff             	test   %rdi,%rdi
    10c7:	49 89 d0             	mov    %rdx,%r8
    10ca:	48 89 ca             	mov    %rcx,%rdx
    10cd:	0f 94 c0             	sete   %al
    10d0:	48 85 f6             	test   %rsi,%rsi
    10d3:	0f 94 c1             	sete   %cl
    10d6:	08 c8                	or     %cl,%al
    10d8:	0f 85 22 01 00 00    	jne    1200 <a15_sm3i_layout_words+0x140>
    10de:	48 85 d2             	test   %rdx,%rdx
    10e1:	0f 84 19 01 00 00    	je     1200 <a15_sm3i_layout_words+0x140>
    10e7:	49 8d 40 f0          	lea    -0x10(%r8),%rax
    10eb:	45 31 c9             	xor    %r9d,%r9d
    10ee:	48 83 e0 ef          	and    $0xffffffffffffffef,%rax
    10f2:	74 0c                	je     1100 <a15_sm3i_layout_words+0x40>
    10f4:	44 89 c8             	mov    %r9d,%eax
    10f7:	c3                   	ret    
    10f8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    10ff:	00 
    1100:	66 0f ef c0          	pxor   %xmm0,%xmm0
    1104:	0f 11 02             	movups %xmm0,(%rdx)
    1107:	0f 11 42 10          	movups %xmm0,0x10(%rdx)
    110b:	0f 11 42 20          	movups %xmm0,0x20(%rdx)
    110f:	0f 11 42 30          	movups %xmm0,0x30(%rdx)
    1113:	0f b6 4f 03          	movzbl 0x3(%rdi),%ecx
    1117:	44 0f b6 4f 08       	movzbl 0x8(%rdi),%r9d
    111c:	c1 e1 18             	shl    $0x18,%ecx
    111f:	41 c1 e1 10          	shl    $0x10,%r9d
    1123:	44 09 c9             	or     %r9d,%ecx
    1126:	44 0f b6 4f 0a       	movzbl 0xa(%rdi),%r9d
    112b:	44 09 c9             	or     %r9d,%ecx
    112e:	44 0f b6 4f 09       	movzbl 0x9(%rdi),%r9d
    1133:	41 c1 e1 08          	shl    $0x8,%r9d
    1137:	44 09 c9             	or     %r9d,%ecx
    113a:	89 0a                	mov    %ecx,(%rdx)
    113c:	8b 4f 0b             	mov    0xb(%rdi),%ecx
    113f:	0f c9                	bswap  %ecx
    1141:	89 4a 04             	mov    %ecx,0x4(%rdx)
    1144:	0f b6 4f 0f          	movzbl 0xf(%rdi),%ecx
    1148:	44 0f b6 4f 13       	movzbl 0x13(%rdi),%r9d
    114d:	c1 e1 18             	shl    $0x18,%ecx
    1150:	41 c1 e1 10          	shl    $0x10,%r9d
    1154:	44 09 c9             	or     %r9d,%ecx
    1157:	44 0f b6 4f 15       	movzbl 0x15(%rdi),%r9d
    115c:	44 09 c9             	or     %r9d,%ecx
    115f:	44 0f b6 4f 14       	movzbl 0x14(%rdi),%r9d
    1164:	41 c1 e1 08          	shl    $0x8,%r9d
    1168:	44 09 c9             	or     %r9d,%ecx
    116b:	4d 89 c1             	mov    %r8,%r9
    116e:	89 4a 08             	mov    %ecx,0x8(%rdx)
    1171:	8b 4f 16             	mov    0x16(%rdi),%ecx
    1174:	49 c1 e9 02          	shr    $0x2,%r9
    1178:	0f c9                	bswap  %ecx
    117a:	89 4a 0c             	mov    %ecx,0xc(%rdx)
    117d:	8b 4f 1a             	mov    0x1a(%rdi),%ecx
    1180:	0f c9                	bswap  %ecx
    1182:	89 4a 10             	mov    %ecx,0x10(%rdx)
    1185:	0f b6 4f 1e          	movzbl 0x1e(%rdi),%ecx
    1189:	0f b6 7f 1f          	movzbl 0x1f(%rdi),%edi
    118d:	c1 e1 18             	shl    $0x18,%ecx
    1190:	c1 e7 10             	shl    $0x10,%edi
    1193:	09 f9                	or     %edi,%ecx
    1195:	0f b7 3e             	movzwl (%rsi),%edi
    1198:	66 c1 c7 08          	rol    $0x8,%di
    119c:	0f b7 ff             	movzwl %di,%edi
    119f:	09 f9                	or     %edi,%ecx
    11a1:	4c 89 cf             	mov    %r9,%rdi
    11a4:	89 4a 14             	mov    %ecx,0x14(%rdx)
    11a7:	48 83 ef 01          	sub    $0x1,%rdi
    11ab:	74 63                	je     1210 <a15_sm3i_layout_words+0x150>
    11ad:	0f 1f 00             	nopl   (%rax)
    11b0:	8b 4c 86 02          	mov    0x2(%rsi,%rax,4),%ecx
    11b4:	0f c9                	bswap  %ecx
    11b6:	89 4c 82 18          	mov    %ecx,0x18(%rdx,%rax,4)
    11ba:	48 83 c0 01          	add    $0x1,%rax
    11be:	48 39 c7             	cmp    %rax,%rdi
    11c1:	75 ed                	jne    11b0 <a15_sm3i_layout_words+0xf0>
    11c3:	4a 8d 3c 8d 14 00 00 	lea    0x14(,%r9,4),%rdi
    11ca:	00 
    11cb:	42 0f b6 44 06 fe    	movzbl -0x2(%rsi,%r8,1),%eax
    11d1:	42 0f b6 4c 06 ff    	movzbl -0x1(%rsi,%r8,1),%ecx
    11d7:	41 b9 01 00 00 00    	mov    $0x1,%r9d
    11dd:	c1 e0 18             	shl    $0x18,%eax
    11e0:	c1 e1 10             	shl    $0x10,%ecx
    11e3:	09 c8                	or     %ecx,%eax
    11e5:	80 cc 80             	or     $0x80,%ah
    11e8:	89 04 3a             	mov    %eax,(%rdx,%rdi,1)
    11eb:	42 8d 04 c5 b0 02 00 	lea    0x2b0(,%r8,8),%eax
    11f2:	00 
    11f3:	89 42 3c             	mov    %eax,0x3c(%rdx)
    11f6:	44 89 c8             	mov    %r9d,%eax
    11f9:	c3                   	ret    
    11fa:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1200:	45 31 c9             	xor    %r9d,%r9d
    1203:	44 89 c8             	mov    %r9d,%eax
    1206:	c3                   	ret    
    1207:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    120e:	00 00 
    1210:	bf 18 00 00 00       	mov    $0x18,%edi
    1215:	eb b4                	jmp    11cb <a15_sm3i_layout_words+0x10b>
    1217:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    121e:	00 00 

0000000000001220 <build_schedule>:
    1220:	41 57                	push   %r15
    1222:	41 56                	push   %r14
    1224:	49 89 fe             	mov    %rdi,%r14
    1227:	41 55                	push   %r13
    1229:	49 8d b6 80 00 00 00 	lea    0x80(%r14),%rsi
    1230:	4d 8d 6e 40          	lea    0x40(%r14),%r13
    1234:	41 54                	push   %r12
    1236:	55                   	push   %rbp
    1237:	53                   	push   %rbx
    1238:	48 81 ec 88 00 00 00 	sub    $0x88,%rsp
    123f:	f3 0f 6f 4f 20       	movdqu 0x20(%rdi),%xmm1
    1244:	f3 0f 6f 57 30       	movdqu 0x30(%rdi),%xmm2
    1249:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    1250:	00 00 
    1252:	48 89 44 24 78       	mov    %rax,0x78(%rsp)
    1257:	31 c0                	xor    %eax,%eax
    1259:	8b 57 54             	mov    0x54(%rdi),%edx
    125c:	8b 47 50             	mov    0x50(%rdi),%eax
    125f:	48 89 74 24 08       	mov    %rsi,0x8(%rsp)
    1264:	41 8b 76 60          	mov    0x60(%r14),%esi
    1268:	8b 7f 64             	mov    0x64(%rdi),%edi
    126b:	0f 29 4c 24 50       	movaps %xmm1,0x50(%rsp)
    1270:	0f 29 54 24 60       	movaps %xmm2,0x60(%rsp)
    1275:	8d 4e fd             	lea    -0x3(%rsi),%ecx
    1278:	83 f9 01             	cmp    $0x1,%ecx
    127b:	0f 86 53 01 00 00    	jbe    13d4 <build_schedule+0x1b4>
    1281:	48 8b 5c 24 08       	mov    0x8(%rsp),%rbx
    1286:	45 31 ff             	xor    %r15d,%r15d
    1289:	48 8d 6c 24 50       	lea    0x50(%rsp),%rbp
    128e:	4c 8d 64 24 10       	lea    0x10(%rsp),%r12
    1293:	e9 b4 00 00 00       	jmp    134c <build_schedule+0x12c>
    1298:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    129f:	00 
    12a0:	e8 00 00 00 00       	call   12a5 <build_schedule+0x85>
    12a5:	8b 44 24 10          	mov    0x10(%rsp),%eax
    12a9:	41 83 c7 01          	add    $0x1,%r15d
    12ad:	48 83 c3 04          	add    $0x4,%rbx
    12b1:	89 43 fc             	mov    %eax,-0x4(%rbx)
    12b4:	8b 44 24 14          	mov    0x14(%rsp),%eax
    12b8:	89 43 1c             	mov    %eax,0x1c(%rbx)
    12bb:	8b 44 24 18          	mov    0x18(%rsp),%eax
    12bf:	89 43 3c             	mov    %eax,0x3c(%rbx)
    12c2:	8b 44 24 1c          	mov    0x1c(%rsp),%eax
    12c6:	89 43 5c             	mov    %eax,0x5c(%rbx)
    12c9:	8b 44 24 20          	mov    0x20(%rsp),%eax
    12cd:	89 43 7c             	mov    %eax,0x7c(%rbx)
    12d0:	8b 44 24 24          	mov    0x24(%rsp),%eax
    12d4:	89 83 9c 00 00 00    	mov    %eax,0x9c(%rbx)
    12da:	8b 44 24 28          	mov    0x28(%rsp),%eax
    12de:	89 83 bc 00 00 00    	mov    %eax,0xbc(%rbx)
    12e4:	8b 44 24 2c          	mov    0x2c(%rsp),%eax
    12e8:	89 83 dc 00 00 00    	mov    %eax,0xdc(%rbx)
    12ee:	8b 44 24 30          	mov    0x30(%rsp),%eax
    12f2:	89 83 fc 00 00 00    	mov    %eax,0xfc(%rbx)
    12f8:	8b 44 24 34          	mov    0x34(%rsp),%eax
    12fc:	89 83 1c 01 00 00    	mov    %eax,0x11c(%rbx)
    1302:	8b 44 24 38          	mov    0x38(%rsp),%eax
    1306:	89 83 3c 01 00 00    	mov    %eax,0x13c(%rbx)
    130c:	8b 44 24 3c          	mov    0x3c(%rsp),%eax
    1310:	89 83 5c 01 00 00    	mov    %eax,0x15c(%rbx)
    1316:	8b 44 24 40          	mov    0x40(%rsp),%eax
    131a:	89 83 7c 01 00 00    	mov    %eax,0x17c(%rbx)
    1320:	8b 44 24 44          	mov    0x44(%rsp),%eax
    1324:	89 83 9c 01 00 00    	mov    %eax,0x19c(%rbx)
    132a:	8b 44 24 48          	mov    0x48(%rsp),%eax
    132e:	89 83 bc 01 00 00    	mov    %eax,0x1bc(%rbx)
    1334:	8b 44 24 4c          	mov    0x4c(%rsp),%eax
    1338:	89 83 dc 01 00 00    	mov    %eax,0x1dc(%rbx)
    133e:	41 83 ff 08          	cmp    $0x8,%r15d
    1342:	74 3f                	je     1383 <build_schedule+0x163>
    1344:	41 8b 46 50          	mov    0x50(%r14),%eax
    1348:	41 8b 56 54          	mov    0x54(%r14),%edx
    134c:	41 8b 4e 5c          	mov    0x5c(%r14),%ecx
    1350:	01 d0                	add    %edx,%eax
    1352:	44 89 fa             	mov    %r15d,%edx
    1355:	4c 89 ee             	mov    %r13,%rsi
    1358:	48 89 ef             	mov    %rbp,%rdi
    135b:	d3 e2                	shl    %cl,%edx
    135d:	4c 89 e1             	mov    %r12,%rcx
    1360:	01 d0                	add    %edx,%eax
    1362:	ba 10 00 00 00       	mov    $0x10,%edx
    1367:	0f c8                	bswap  %eax
    1369:	89 44 24 6c          	mov    %eax,0x6c(%rsp)
    136d:	41 8b 46 64          	mov    0x64(%r14),%eax
    1371:	85 c0                	test   %eax,%eax
    1373:	0f 85 27 ff ff ff    	jne    12a0 <build_schedule+0x80>
    1379:	e8 f2 f3 ff ff       	call   770 <layout_bytes>
    137e:	e9 22 ff ff ff       	jmp    12a5 <build_schedule+0x85>
    1383:	48 8b 74 24 08       	mov    0x8(%rsp),%rsi
    1388:	48 89 f7             	mov    %rsi,%rdi
    138b:	e8 20 ef ff ff       	call   2b0 <expand8>
    1390:	66 0f ef c0          	pxor   %xmm0,%xmm0
    1394:	0f 29 44 24 10       	movaps %xmm0,0x10(%rsp)
    1399:	0f 29 44 24 20       	movaps %xmm0,0x20(%rsp)
    139e:	0f 29 44 24 30       	movaps %xmm0,0x30(%rsp)
    13a3:	0f 29 44 24 40       	movaps %xmm0,0x40(%rsp)
    13a8:	0f 29 44 24 50       	movaps %xmm0,0x50(%rsp)
    13ad:	0f 29 44 24 60       	movaps %xmm0,0x60(%rsp)
    13b2:	48 8b 44 24 78       	mov    0x78(%rsp),%rax
    13b7:	64 48 2b 04 25 28 00 	sub    %fs:0x28,%rax
    13be:	00 00 
    13c0:	75 50                	jne    1412 <build_schedule+0x1f2>
    13c2:	48 81 c4 88 00 00 00 	add    $0x88,%rsp
    13c9:	5b                   	pop    %rbx
    13ca:	5d                   	pop    %rbp
    13cb:	41 5c                	pop    %r12
    13cd:	41 5d                	pop    %r13
    13cf:	41 5e                	pop    %r14
    13d1:	41 5f                	pop    %r15
    13d3:	c3                   	ret    
    13d4:	01 d0                	add    %edx,%eax
    13d6:	48 8d 6c 24 50       	lea    0x50(%rsp),%rbp
    13db:	85 ff                	test   %edi,%edi
    13dd:	48 8b 4c 24 08       	mov    0x8(%rsp),%rcx
    13e2:	0f c8                	bswap  %eax
    13e4:	ba 10 00 00 00       	mov    $0x10,%edx
    13e9:	89 44 24 6c          	mov    %eax,0x6c(%rsp)
    13ed:	4c 89 ee             	mov    %r13,%rsi
    13f0:	48 89 ef             	mov    %rbp,%rdi
    13f3:	75 16                	jne    140b <build_schedule+0x1eb>
    13f5:	e8 76 f3 ff ff       	call   770 <layout_bytes>
    13fa:	48 8b 7c 24 08       	mov    0x8(%rsp),%rdi
    13ff:	4c 8d 64 24 10       	lea    0x10(%rsp),%r12
    1404:	e8 f7 eb ff ff       	call   0 <expand>
    1409:	eb 85                	jmp    1390 <build_schedule+0x170>
    140b:	e8 00 00 00 00       	call   1410 <build_schedule+0x1f0>
    1410:	eb e8                	jmp    13fa <build_schedule+0x1da>
    1412:	e8 00 00 00 00       	call   1417 <build_schedule+0x1f7>
    1417:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    141e:	00 00 

0000000000001420 <a15_sm3i_thash8>:
    1420:	f3 0f 1e fa          	endbr64 
    1424:	41 57                	push   %r15
    1426:	41 56                	push   %r14
    1428:	41 55                	push   %r13
    142a:	41 54                	push   %r12
    142c:	55                   	push   %rbp
    142d:	53                   	push   %rbx
    142e:	48 81 ec f8 0b 00 00 	sub    $0xbf8,%rsp
    1435:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    143c:	00 00 
    143e:	48 89 84 24 e8 0b 00 	mov    %rax,0xbe8(%rsp)
    1445:	00 
    1446:	31 c0                	xor    %eax,%eax
    1448:	48 85 ff             	test   %rdi,%rdi
    144b:	74 33                	je     1480 <a15_sm3i_thash8+0x60>
    144d:	48 85 f6             	test   %rsi,%rsi
    1450:	74 2e                	je     1480 <a15_sm3i_thash8+0x60>
    1452:	48 89 34 24          	mov    %rsi,(%rsp)
    1456:	49 89 d6             	mov    %rdx,%r14
    1459:	48 85 d2             	test   %rdx,%rdx
    145c:	74 22                	je     1480 <a15_sm3i_thash8+0x60>
    145e:	4d 89 cc             	mov    %r9,%r12
    1461:	4d 85 c9             	test   %r9,%r9
    1464:	74 1a                	je     1480 <a15_sm3i_thash8+0x60>
    1466:	48 8d 41 f0          	lea    -0x10(%rcx),%rax
    146a:	49 89 cd             	mov    %rcx,%r13
    146d:	48 a9 ef ff ff ff    	test   $0xffffffffffffffef,%rax
    1473:	75 0b                	jne    1480 <a15_sm3i_thash8+0x60>
    1475:	41 83 f8 01          	cmp    $0x1,%r8d
    1479:	44 89 44 24 14       	mov    %r8d,0x14(%rsp)
    147e:	76 30                	jbe    14b0 <a15_sm3i_thash8+0x90>
    1480:	31 c0                	xor    %eax,%eax
    1482:	48 8b 94 24 e8 0b 00 	mov    0xbe8(%rsp),%rdx
    1489:	00 
    148a:	64 48 2b 14 25 28 00 	sub    %fs:0x28,%rdx
    1491:	00 00 
    1493:	0f 85 5b 02 00 00    	jne    16f4 <a15_sm3i_thash8+0x2d4>
    1499:	48 81 c4 f8 0b 00 00 	add    $0xbf8,%rsp
    14a0:	5b                   	pop    %rbx
    14a1:	5d                   	pop    %rbp
    14a2:	41 5c                	pop    %r12
    14a4:	41 5d                	pop    %r13
    14a6:	41 5e                	pop    %r14
    14a8:	41 5f                	pop    %r15
    14aa:	c3                   	ret    
    14ab:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    14b0:	48 89 fd             	mov    %rdi,%rbp
    14b3:	e8 00 00 00 00       	call   14b8 <a15_sm3i_thash8+0x98>
    14b8:	85 c0                	test   %eax,%eax
    14ba:	74 c4                	je     1480 <a15_sm3i_thash8+0x60>
    14bc:	49 83 3e 00          	cmpq   $0x0,(%r14)
    14c0:	74 be                	je     1480 <a15_sm3i_thash8+0x60>
    14c2:	49 83 7e 08 00       	cmpq   $0x0,0x8(%r14)
    14c7:	74 b7                	je     1480 <a15_sm3i_thash8+0x60>
    14c9:	49 83 7e 10 00       	cmpq   $0x0,0x10(%r14)
    14ce:	74 b0                	je     1480 <a15_sm3i_thash8+0x60>
    14d0:	49 83 7e 18 00       	cmpq   $0x0,0x18(%r14)
    14d5:	74 a9                	je     1480 <a15_sm3i_thash8+0x60>
    14d7:	49 83 7e 20 00       	cmpq   $0x0,0x20(%r14)
    14dc:	74 a2                	je     1480 <a15_sm3i_thash8+0x60>
    14de:	49 83 7e 28 00       	cmpq   $0x0,0x28(%r14)
    14e3:	74 9b                	je     1480 <a15_sm3i_thash8+0x60>
    14e5:	49 83 7e 30 00       	cmpq   $0x0,0x30(%r14)
    14ea:	74 94                	je     1480 <a15_sm3i_thash8+0x60>
    14ec:	49 83 7e 38 00       	cmpq   $0x0,0x38(%r14)
    14f1:	74 8d                	je     1480 <a15_sm3i_thash8+0x60>
    14f3:	48 8d 84 24 60 01 00 	lea    0x160(%rsp),%rax
    14fa:	00 
    14fb:	4c 8b 3c 24          	mov    (%rsp),%r15
    14ff:	44 8b 44 24 14       	mov    0x14(%rsp),%r8d
    1504:	48 89 44 24 18       	mov    %rax,0x18(%rsp)
    1509:	48 89 c3             	mov    %rax,%rbx
    150c:	48 8d 84 24 80 01 00 	lea    0x180(%rsp),%rax
    1513:	00 
    1514:	48 89 44 24 08       	mov    %rax,0x8(%rsp)
    1519:	48 8d 44 24 20       	lea    0x20(%rsp),%rax
    151e:	48 89 04 24          	mov    %rax,(%rsp)
    1522:	e9 b7 00 00 00       	jmp    15de <a15_sm3i_thash8+0x1be>
    1527:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    152e:	00 00 
    1530:	e8 00 00 00 00       	call   1535 <a15_sm3i_thash8+0x115>
    1535:	44 8b 44 24 14       	mov    0x14(%rsp),%r8d
    153a:	8b 44 24 20          	mov    0x20(%rsp),%eax
    153e:	49 83 c6 08          	add    $0x8,%r14
    1542:	48 83 c3 04          	add    $0x4,%rbx
    1546:	49 83 c7 20          	add    $0x20,%r15
    154a:	89 43 fc             	mov    %eax,-0x4(%rbx)
    154d:	8b 44 24 24          	mov    0x24(%rsp),%eax
    1551:	89 43 1c             	mov    %eax,0x1c(%rbx)
    1554:	8b 44 24 28          	mov    0x28(%rsp),%eax
    1558:	89 43 3c             	mov    %eax,0x3c(%rbx)
    155b:	8b 44 24 2c          	mov    0x2c(%rsp),%eax
    155f:	89 43 5c             	mov    %eax,0x5c(%rbx)
    1562:	8b 44 24 30          	mov    0x30(%rsp),%eax
    1566:	89 43 7c             	mov    %eax,0x7c(%rbx)
    1569:	8b 44 24 34          	mov    0x34(%rsp),%eax
    156d:	89 83 9c 00 00 00    	mov    %eax,0x9c(%rbx)
    1573:	8b 44 24 38          	mov    0x38(%rsp),%eax
    1577:	89 83 bc 00 00 00    	mov    %eax,0xbc(%rbx)
    157d:	8b 44 24 3c          	mov    0x3c(%rsp),%eax
    1581:	89 83 dc 00 00 00    	mov    %eax,0xdc(%rbx)
    1587:	8b 44 24 40          	mov    0x40(%rsp),%eax
    158b:	89 83 fc 00 00 00    	mov    %eax,0xfc(%rbx)
    1591:	8b 44 24 44          	mov    0x44(%rsp),%eax
    1595:	89 83 1c 01 00 00    	mov    %eax,0x11c(%rbx)
    159b:	8b 44 24 48          	mov    0x48(%rsp),%eax
    159f:	89 83 3c 01 00 00    	mov    %eax,0x13c(%rbx)
    15a5:	8b 44 24 4c          	mov    0x4c(%rsp),%eax
    15a9:	89 83 5c 01 00 00    	mov    %eax,0x15c(%rbx)
    15af:	8b 44 24 50          	mov    0x50(%rsp),%eax
    15b3:	89 83 7c 01 00 00    	mov    %eax,0x17c(%rbx)
    15b9:	8b 44 24 54          	mov    0x54(%rsp),%eax
    15bd:	89 83 9c 01 00 00    	mov    %eax,0x19c(%rbx)
    15c3:	8b 44 24 58          	mov    0x58(%rsp),%eax
    15c7:	89 83 bc 01 00 00    	mov    %eax,0x1bc(%rbx)
    15cd:	8b 44 24 5c          	mov    0x5c(%rsp),%eax
    15d1:	89 83 dc 01 00 00    	mov    %eax,0x1dc(%rbx)
    15d7:	48 39 5c 24 08       	cmp    %rbx,0x8(%rsp)
    15dc:	74 2a                	je     1608 <a15_sm3i_thash8+0x1e8>
    15de:	44 89 44 24 14       	mov    %r8d,0x14(%rsp)
    15e3:	49 8b 36             	mov    (%r14),%rsi
    15e6:	4c 89 ea             	mov    %r13,%rdx
    15e9:	4c 89 ff             	mov    %r15,%rdi
    15ec:	48 8b 0c 24          	mov    (%rsp),%rcx
    15f0:	45 85 c0             	test   %r8d,%r8d
    15f3:	0f 85 37 ff ff ff    	jne    1530 <a15_sm3i_thash8+0x110>
    15f9:	e8 72 f1 ff ff       	call   770 <layout_bytes>
    15fe:	44 8b 44 24 14       	mov    0x14(%rsp),%r8d
    1603:	e9 32 ff ff ff       	jmp    153a <a15_sm3i_thash8+0x11a>
    1608:	4c 8b 7c 24 18       	mov    0x18(%rsp),%r15
    160d:	4c 8d b4 24 60 03 00 	lea    0x360(%rsp),%r14
    1614:	00 
    1615:	48 8d 5c 24 60       	lea    0x60(%rsp),%rbx
    161a:	4c 89 f6             	mov    %r14,%rsi
    161d:	49 89 d8             	mov    %rbx,%r8
    1620:	4c 89 ff             	mov    %r15,%rdi
    1623:	e8 88 ec ff ff       	call   2b0 <expand8>
    1628:	31 c9                	xor    %ecx,%ecx
    162a:	48 89 ef             	mov    %rbp,%rdi
    162d:	31 d2                	xor    %edx,%edx
    162f:	4c 89 f6             	mov    %r14,%rsi
    1632:	e8 d9 f6 ff ff       	call   d10 <rounds8.constprop.0>
    1637:	66 0f 6f 4c 24 60    	movdqa 0x60(%rsp),%xmm1
    163d:	31 c0                	xor    %eax,%eax
    163f:	4c 89 ff             	mov    %r15,%rdi
    1642:	66 0f 6f 94 24 80 00 	movdqa 0x80(%rsp),%xmm2
    1649:	00 00 
    164b:	b9 40 00 00 00       	mov    $0x40,%ecx
    1650:	66 0f 6f 9c 24 a0 00 	movdqa 0xa0(%rsp),%xmm3
    1657:	00 00 
    1659:	66 0f 6f a4 24 c0 00 	movdqa 0xc0(%rsp),%xmm4
    1660:	00 00 
    1662:	41 0f 11 0c 24       	movups %xmm1,(%r12)
    1667:	66 0f 6f ac 24 e0 00 	movdqa 0xe0(%rsp),%xmm5
    166e:	00 00 
    1670:	66 0f 6f b4 24 00 01 	movdqa 0x100(%rsp),%xmm6
    1677:	00 00 
    1679:	41 0f 11 54 24 10    	movups %xmm2,0x10(%r12)
    167f:	66 0f 6f bc 24 20 01 	movdqa 0x120(%rsp),%xmm7
    1686:	00 00 
    1688:	66 0f 6f 8c 24 40 01 	movdqa 0x140(%rsp),%xmm1
    168f:	00 00 
    1691:	41 0f 11 5c 24 20    	movups %xmm3,0x20(%r12)
    1697:	f3 48 ab             	rep stos %rax,%es:(%rdi)
    169a:	41 0f 11 64 24 30    	movups %xmm4,0x30(%r12)
    16a0:	41 0f 11 6c 24 40    	movups %xmm5,0x40(%r12)
    16a6:	41 0f 11 74 24 50    	movups %xmm6,0x50(%r12)
    16ac:	41 0f 11 7c 24 60    	movups %xmm7,0x60(%r12)
    16b2:	41 0f 11 4c 24 70    	movups %xmm1,0x70(%r12)
    16b8:	66 0f ef c0          	pxor   %xmm0,%xmm0
    16bc:	48 8b 0c 24          	mov    (%rsp),%rcx
    16c0:	0f 29 44 24 20       	movaps %xmm0,0x20(%rsp)
    16c5:	0f 29 44 24 30       	movaps %xmm0,0x30(%rsp)
    16ca:	0f 29 44 24 40       	movaps %xmm0,0x40(%rsp)
    16cf:	0f 29 44 24 50       	movaps %xmm0,0x50(%rsp)
    16d4:	b9 10 01 00 00       	mov    $0x110,%ecx
    16d9:	4c 89 f7             	mov    %r14,%rdi
    16dc:	f3 48 ab             	rep stos %rax,%es:(%rdi)
    16df:	b9 20 00 00 00       	mov    $0x20,%ecx
    16e4:	48 89 df             	mov    %rbx,%rdi
    16e7:	f3 48 ab             	rep stos %rax,%es:(%rdi)
    16ea:	b8 01 00 00 00       	mov    $0x1,%eax
    16ef:	e9 8e fd ff ff       	jmp    1482 <a15_sm3i_thash8+0x62>
    16f4:	e8 00 00 00 00       	call   16f9 <a15_sm3i_thash8+0x2d9>
    16f9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001700 <a15_sm3i_clear>:
    1700:	f3 0f 1e fa          	endbr64 
    1704:	48 89 fa             	mov    %rdi,%rdx
    1707:	48 85 ff             	test   %rdi,%rdi
    170a:	74 2e                	je     173a <a15_sm3i_clear+0x3a>
    170c:	48 c7 07 00 00 00 00 	movq   $0x0,(%rdi)
    1713:	48 8d 7f 08          	lea    0x8(%rdi),%rdi
    1717:	48 89 d1             	mov    %rdx,%rcx
    171a:	31 c0                	xor    %eax,%eax
    171c:	48 c7 87 f0 08 00 00 	movq   $0x0,0x8f0(%rdi)
    1723:	00 00 00 00 
    1727:	48 83 e7 f8          	and    $0xfffffffffffffff8,%rdi
    172b:	48 29 f9             	sub    %rdi,%rcx
    172e:	81 c1 00 09 00 00    	add    $0x900,%ecx
    1734:	c1 e9 03             	shr    $0x3,%ecx
    1737:	f3 48 ab             	rep stos %rax,%es:(%rdi)
    173a:	c3                   	ret    
    173b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001740 <a15_sm3i_init>:
    1740:	f3 0f 1e fa          	endbr64 
    1744:	41 57                	push   %r15
    1746:	41 56                	push   %r14
    1748:	41 55                	push   %r13
    174a:	41 54                	push   %r12
    174c:	55                   	push   %rbp
    174d:	53                   	push   %rbx
    174e:	48 83 ec 18          	sub    $0x18,%rsp
    1752:	48 85 ff             	test   %rdi,%rdi
    1755:	0f 84 3b 02 00 00    	je     1996 <a15_sm3i_init+0x256>
    175b:	48 85 d2             	test   %rdx,%rdx
    175e:	49 89 d4             	mov    %rdx,%r12
    1761:	48 89 fd             	mov    %rdi,%rbp
    1764:	49 89 cd             	mov    %rcx,%r13
    1767:	0f 94 c0             	sete   %al
    176a:	48 85 c9             	test   %rcx,%rcx
    176d:	0f 94 c2             	sete   %dl
    1770:	08 d0                	or     %dl,%al
    1772:	0f 85 ef 01 00 00    	jne    1967 <a15_sm3i_init+0x227>
    1778:	48 85 f6             	test   %rsi,%rsi
    177b:	0f 84 e6 01 00 00    	je     1967 <a15_sm3i_init+0x227>
    1781:	48 39 f7             	cmp    %rsi,%rdi
    1784:	0f 86 26 02 00 00    	jbe    19b0 <a15_sm3i_init+0x270>
    178a:	48 89 f8             	mov    %rdi,%rax
    178d:	48 29 f0             	sub    %rsi,%rax
    1790:	48 83 f8 1f          	cmp    $0x1f,%rax
    1794:	0f 96 c0             	setbe  %al
    1797:	0f b6 c0             	movzbl %al,%eax
    179a:	85 c0                	test   %eax,%eax
    179c:	0f 85 c5 01 00 00    	jne    1967 <a15_sm3i_init+0x227>
    17a2:	4c 39 e5             	cmp    %r12,%rbp
    17a5:	0f 86 25 02 00 00    	jbe    19d0 <a15_sm3i_init+0x290>
    17ab:	48 89 e8             	mov    %rbp,%rax
    17ae:	4c 29 e0             	sub    %r12,%rax
    17b1:	48 83 f8 1f          	cmp    $0x1f,%rax
    17b5:	0f 96 c0             	setbe  %al
    17b8:	0f b6 c0             	movzbl %al,%eax
    17bb:	85 c0                	test   %eax,%eax
    17bd:	0f 85 a4 01 00 00    	jne    1967 <a15_sm3i_init+0x227>
    17c3:	4c 39 ed             	cmp    %r13,%rbp
    17c6:	0f 87 24 02 00 00    	ja     19f0 <a15_sm3i_init+0x2b0>
    17cc:	4c 89 e8             	mov    %r13,%rax
    17cf:	45 31 f6             	xor    %r14d,%r14d
    17d2:	48 29 e8             	sub    %rbp,%rax
    17d5:	48 3d ff 08 00 00    	cmp    $0x8ff,%rax
    17db:	41 0f 96 c6          	setbe  %r14b
    17df:	45 85 f6             	test   %r14d,%r14d
    17e2:	0f 85 7f 01 00 00    	jne    1967 <a15_sm3i_init+0x227>
    17e8:	48 8d 7d 08          	lea    0x8(%rbp),%rdi
    17ec:	48 89 e9             	mov    %rbp,%rcx
    17ef:	31 c0                	xor    %eax,%eax
    17f1:	48 89 34 24          	mov    %rsi,(%rsp)
    17f5:	48 83 e7 f8          	and    $0xfffffffffffffff8,%rdi
    17f9:	48 c7 45 00 00 00 00 	movq   $0x0,0x0(%rbp)
    1800:	00 
    1801:	48 c7 85 f8 08 00 00 	movq   $0x0,0x8f8(%rbp)
    1808:	00 00 00 00 
    180c:	48 29 f9             	sub    %rdi,%rcx
    180f:	81 c1 00 09 00 00    	add    $0x900,%ecx
    1815:	c1 e9 03             	shr    $0x3,%ecx
    1818:	f3 48 ab             	rep stos %rax,%es:(%rdi)
    181b:	83 7c 24 50 03       	cmpl   $0x3,0x50(%rsp)
    1820:	0f 85 70 01 00 00    	jne    1996 <a15_sm3i_init+0x256>
    1826:	83 7c 24 58 18       	cmpl   $0x18,0x58(%rsp)
    182b:	0f 85 65 01 00 00    	jne    1996 <a15_sm3i_init+0x256>
    1831:	83 7c 24 60 06       	cmpl   $0x6,0x60(%rsp)
    1836:	45 8d 79 fd          	lea    -0x3(%r9),%r15d
    183a:	0f 85 56 01 00 00    	jne    1996 <a15_sm3i_init+0x256>
    1840:	41 83 ff 15          	cmp    $0x15,%r15d
    1844:	0f 87 4c 01 00 00    	ja     1996 <a15_sm3i_init+0x256>
    184a:	8b 44 24 68          	mov    0x68(%rsp),%eax
    184e:	83 e8 01             	sub    $0x1,%eax
    1851:	83 f8 03             	cmp    $0x3,%eax
    1854:	0f 87 3c 01 00 00    	ja     1996 <a15_sm3i_init+0x256>
    185a:	83 7c 24 70 01       	cmpl   $0x1,0x70(%rsp)
    185f:	0f 87 31 01 00 00    	ja     1996 <a15_sm3i_init+0x256>
    1865:	44 89 c9             	mov    %r9d,%ecx
    1868:	b8 01 00 00 00       	mov    $0x1,%eax
    186d:	44 89 c2             	mov    %r8d,%edx
    1870:	44 89 44 24 0c       	mov    %r8d,0xc(%rsp)
    1875:	48 d3 e0             	shl    %cl,%rax
    1878:	48 8d 48 ff          	lea    -0x1(%rax),%rcx
    187c:	48 85 d1             	test   %rdx,%rcx
    187f:	0f 85 11 01 00 00    	jne    1996 <a15_sm3i_init+0x256>
    1885:	48 01 c2             	add    %rax,%rdx
    1888:	48 81 fa 00 00 00 06 	cmp    $0x6000000,%rdx
    188f:	0f 87 01 01 00 00    	ja     1996 <a15_sm3i_init+0x256>
    1895:	41 83 f9 03          	cmp    $0x3,%r9d
    1899:	0f 84 fd 00 00 00    	je     199c <a15_sm3i_init+0x25c>
    189f:	e8 00 00 00 00       	call   18a4 <a15_sm3i_init+0x164>
    18a4:	85 c0                	test   %eax,%eax
    18a6:	0f 84 f0 00 00 00    	je     199c <a15_sm3i_init+0x25c>
    18ac:	48 8b 34 24          	mov    (%rsp),%rsi
    18b0:	44 8b 44 24 0c       	mov    0xc(%rsp),%r8d
    18b5:	44 89 f9             	mov    %r15d,%ecx
    18b8:	66 0f 6e 4c 24 68    	movd   0x68(%rsp),%xmm1
    18be:	f3 0f 6f 1e          	movdqu (%rsi),%xmm3
    18c2:	44 89 c0             	mov    %r8d,%eax
    18c5:	0f c8                	bswap  %eax
    18c7:	0f 11 5d 00          	movups %xmm3,0x0(%rbp)
    18cb:	f3 0f 6f 66 10       	movdqu 0x10(%rsi),%xmm4
    18d0:	66 0f 6e 5c 24 70    	movd   0x70(%rsp),%xmm3
    18d6:	0f 11 65 10          	movups %xmm4,0x10(%rbp)
    18da:	f3 41 0f 6f 2c 24    	movdqu (%r12),%xmm5
    18e0:	66 41 0f 6e e7       	movd   %r15d,%xmm4
    18e5:	66 0f 62 cb          	punpckldq %xmm3,%xmm1
    18e9:	0f 11 6d 20          	movups %xmm5,0x20(%rbp)
    18ed:	f3 41 0f 6f 74 24 10 	movdqu 0x10(%r12),%xmm6
    18f4:	0f 11 75 30          	movups %xmm6,0x30(%rbp)
    18f8:	f3 41 0f 6f 7d 00    	movdqu 0x0(%r13),%xmm7
    18fe:	89 45 3c             	mov    %eax,0x3c(%rbp)
    1901:	b8 01 00 00 00       	mov    $0x1,%eax
    1906:	d3 e0                	shl    %cl,%eax
    1908:	c7 45 30 00 00 00 06 	movl   $0x6000000,0x30(%rbp)
    190f:	66 0f 6e c0          	movd   %eax,%xmm0
    1913:	8b 44 24 68          	mov    0x68(%rsp),%eax
    1917:	c7 45 38 00 00 00 00 	movl   $0x0,0x38(%rbp)
    191e:	66 0f 62 c4          	punpckldq %xmm4,%xmm0
    1922:	44 89 45 50          	mov    %r8d,0x50(%rbp)
    1926:	66 0f 6c c1          	punpcklqdq %xmm1,%xmm0
    192a:	83 e8 03             	sub    $0x3,%eax
    192d:	c7 45 68 01 00 00 00 	movl   $0x1,0x68(%rbp)
    1934:	0f 11 7d 40          	movups %xmm7,0x40(%rbp)
    1938:	0f 11 45 58          	movups %xmm0,0x58(%rbp)
    193c:	83 f8 01             	cmp    $0x1,%eax
    193f:	0f 86 5b 01 00 00    	jbe    1aa0 <a15_sm3i_init+0x360>
    1945:	8b 44 24 68          	mov    0x68(%rsp),%eax
    1949:	44 8d 58 fe          	lea    -0x2(%rax),%r11d
    194d:	41 83 e3 fd          	and    $0xfffffffd,%r11d
    1951:	0f 84 af 00 00 00    	je     1a06 <a15_sm3i_init+0x2c6>
    1957:	48 89 ef             	mov    %rbp,%rdi
    195a:	41 be 01 00 00 00    	mov    $0x1,%r14d
    1960:	e8 bb f8 ff ff       	call   1220 <build_schedule>
    1965:	eb 35                	jmp    199c <a15_sm3i_init+0x25c>
    1967:	48 8d 7d 08          	lea    0x8(%rbp),%rdi
    196b:	48 89 e9             	mov    %rbp,%rcx
    196e:	31 c0                	xor    %eax,%eax
    1970:	48 c7 45 00 00 00 00 	movq   $0x0,0x0(%rbp)
    1977:	00 
    1978:	48 c7 85 f8 08 00 00 	movq   $0x0,0x8f8(%rbp)
    197f:	00 00 00 00 
    1983:	48 83 e7 f8          	and    $0xfffffffffffffff8,%rdi
    1987:	48 29 f9             	sub    %rdi,%rcx
    198a:	81 c1 00 09 00 00    	add    $0x900,%ecx
    1990:	c1 e9 03             	shr    $0x3,%ecx
    1993:	f3 48 ab             	rep stos %rax,%es:(%rdi)
    1996:	41 be ff ff ff ff    	mov    $0xffffffff,%r14d
    199c:	48 83 c4 18          	add    $0x18,%rsp
    19a0:	44 89 f0             	mov    %r14d,%eax
    19a3:	5b                   	pop    %rbx
    19a4:	5d                   	pop    %rbp
    19a5:	41 5c                	pop    %r12
    19a7:	41 5d                	pop    %r13
    19a9:	41 5e                	pop    %r14
    19ab:	41 5f                	pop    %r15
    19ad:	c3                   	ret    
    19ae:	66 90                	xchg   %ax,%ax
    19b0:	48 89 f0             	mov    %rsi,%rax
    19b3:	48 29 f8             	sub    %rdi,%rax
    19b6:	48 3d ff 08 00 00    	cmp    $0x8ff,%rax
    19bc:	0f 96 c0             	setbe  %al
    19bf:	0f b6 c0             	movzbl %al,%eax
    19c2:	e9 d3 fd ff ff       	jmp    179a <a15_sm3i_init+0x5a>
    19c7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    19ce:	00 00 
    19d0:	4c 89 e0             	mov    %r12,%rax
    19d3:	48 29 e8             	sub    %rbp,%rax
    19d6:	48 3d ff 08 00 00    	cmp    $0x8ff,%rax
    19dc:	0f 96 c0             	setbe  %al
    19df:	0f b6 c0             	movzbl %al,%eax
    19e2:	e9 d4 fd ff ff       	jmp    17bb <a15_sm3i_init+0x7b>
    19e7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    19ee:	00 00 
    19f0:	48 89 e8             	mov    %rbp,%rax
    19f3:	45 31 f6             	xor    %r14d,%r14d
    19f6:	4c 29 e8             	sub    %r13,%rax
    19f9:	48 83 f8 0f          	cmp    $0xf,%rax
    19fd:	41 0f 96 c6          	setbe  %r14b
    1a01:	e9 d9 fd ff ff       	jmp    17df <a15_sm3i_init+0x9f>
    1a06:	8b 05 00 00 00 00    	mov    0x0(%rip),%eax        # 1a0c <a15_sm3i_init+0x2cc>
    1a0c:	83 f8 02             	cmp    $0x2,%eax
    1a0f:	0f 84 a7 00 00 00    	je     1abc <a15_sm3i_init+0x37c>
    1a15:	ba 01 00 00 00       	mov    $0x1,%edx
    1a1a:	44 89 d8             	mov    %r11d,%eax
    1a1d:	f0 0f b1 15 00 00 00 	lock cmpxchg %edx,0x0(%rip)        # 1a25 <a15_sm3i_init+0x2e5>
    1a24:	00 
    1a25:	0f 85 86 00 00 00    	jne    1ab1 <a15_sm3i_init+0x371>
    1a2b:	4c 8d 25 00 00 00 00 	lea    0x0(%rip),%r12        # 1a32 <a15_sm3i_init+0x2f2>
    1a32:	bb 01 00 00 00       	mov    $0x1,%ebx
    1a37:	4d 89 e2             	mov    %r12,%r10
    1a3a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1a40:	41 83 c3 01          	add    $0x1,%r11d
    1a44:	89 da                	mov    %ebx,%edx
    1a46:	31 c0                	xor    %eax,%eax
    1a48:	4c 89 d7             	mov    %r10,%rdi
    1a4b:	44 89 d9             	mov    %r11d,%ecx
    1a4e:	d3 e2                	shl    %cl,%edx
    1a50:	b9 22 00 00 00       	mov    $0x22,%ecx
    1a55:	f3 48 ab             	rep stos %rax,%es:(%rdi)
    1a58:	83 ea 01             	sub    $0x1,%edx
    1a5b:	4c 89 d7             	mov    %r10,%rdi
    1a5e:	49 81 c2 10 01 00 00 	add    $0x110,%r10
    1a65:	89 d0                	mov    %edx,%eax
    1a67:	c1 e2 10             	shl    $0x10,%edx
    1a6a:	c1 e8 10             	shr    $0x10,%eax
    1a6d:	66 0f 6e d2          	movd   %edx,%xmm2
    1a71:	66 0f 6e c0          	movd   %eax,%xmm0
    1a75:	66 0f 62 c2          	punpckldq %xmm2,%xmm0
    1a79:	66 41 0f d6 82 00 ff 	movq   %xmm0,-0x100(%r10)
    1a80:	ff ff 
    1a82:	e8 79 e5 ff ff       	call   0 <expand>
    1a87:	41 83 fb 15          	cmp    $0x15,%r11d
    1a8b:	75 b3                	jne    1a40 <a15_sm3i_init+0x300>
    1a8d:	c7 05 00 00 00 00 02 	movl   $0x2,0x0(%rip)        # 1a97 <a15_sm3i_init+0x357>
    1a94:	00 00 00 
    1a97:	4c 89 65 78          	mov    %r12,0x78(%rbp)
    1a9b:	e9 b7 fe ff ff       	jmp    1957 <a15_sm3i_init+0x217>
    1aa0:	44 89 ff             	mov    %r15d,%edi
    1aa3:	e8 88 ea ff ff       	call   530 <prepare_offsets>
    1aa8:	48 89 45 70          	mov    %rax,0x70(%rbp)
    1aac:	e9 94 fe ff ff       	jmp    1945 <a15_sm3i_init+0x205>
    1ab1:	8b 05 00 00 00 00    	mov    0x0(%rip),%eax        # 1ab7 <a15_sm3i_init+0x377>
    1ab7:	83 f8 02             	cmp    $0x2,%eax
    1aba:	75 f5                	jne    1ab1 <a15_sm3i_init+0x371>
    1abc:	4c 8d 25 00 00 00 00 	lea    0x0(%rip),%r12        # 1ac3 <a15_sm3i_init+0x383>
    1ac3:	eb d2                	jmp    1a97 <a15_sm3i_init+0x357>
    1ac5:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
    1acc:	00 00 00 00 

0000000000001ad0 <a15_sm3i_consume>:
    1ad0:	f3 0f 1e fa          	endbr64 
    1ad4:	55                   	push   %rbp
    1ad5:	53                   	push   %rbx
    1ad6:	48 81 ec 18 01 00 00 	sub    $0x118,%rsp
    1add:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    1ae4:	00 00 
    1ae6:	48 89 84 24 08 01 00 	mov    %rax,0x108(%rsp)
    1aed:	00 
    1aee:	31 c0                	xor    %eax,%eax
    1af0:	48 85 ff             	test   %rdi,%rdi
    1af3:	0f 84 07 01 00 00    	je     1c00 <a15_sm3i_consume+0x130>
    1af9:	48 89 f3             	mov    %rsi,%rbx
    1afc:	48 85 f6             	test   %rsi,%rsi
    1aff:	0f 84 fb 00 00 00    	je     1c00 <a15_sm3i_consume+0x130>
    1b05:	48 39 f7             	cmp    %rsi,%rdi
    1b08:	0f 86 da 00 00 00    	jbe    1be8 <a15_sm3i_consume+0x118>
    1b0e:	48 89 fa             	mov    %rdi,%rdx
    1b11:	31 c0                	xor    %eax,%eax
    1b13:	48 29 f2             	sub    %rsi,%rdx
    1b16:	48 83 fa 7f          	cmp    $0x7f,%rdx
    1b1a:	0f 86 a8 00 00 00    	jbe    1bc8 <a15_sm3i_consume+0xf8>
    1b20:	8b 47 68             	mov    0x68(%rdi),%eax
    1b23:	85 c0                	test   %eax,%eax
    1b25:	0f 84 dd 00 00 00    	je     1c08 <a15_sm3i_consume+0x138>
    1b2b:	8b 47 58             	mov    0x58(%rdi),%eax
    1b2e:	39 47 54             	cmp    %eax,0x54(%rdi)
    1b31:	0f 83 d1 00 00 00    	jae    1c08 <a15_sm3i_consume+0x138>
    1b37:	8b 47 60             	mov    0x60(%rdi),%eax
    1b3a:	48 8d b7 80 00 00 00 	lea    0x80(%rdi),%rsi
    1b41:	48 89 e5             	mov    %rsp,%rbp
    1b44:	83 e8 03             	sub    $0x3,%eax
    1b47:	83 f8 01             	cmp    $0x1,%eax
    1b4a:	0f 86 e8 00 00 00    	jbe    1c38 <a15_sm3i_consume+0x168>
    1b50:	49 89 e8             	mov    %rbp,%r8
    1b53:	31 c9                	xor    %ecx,%ecx
    1b55:	31 d2                	xor    %edx,%edx
    1b57:	e8 b4 f1 ff ff       	call   d10 <rounds8.constprop.0>
    1b5c:	66 0f 6f 04 24       	movdqa (%rsp),%xmm0
    1b61:	66 0f 6f 4c 24 20    	movdqa 0x20(%rsp),%xmm1
    1b67:	31 c0                	xor    %eax,%eax
    1b69:	48 89 ef             	mov    %rbp,%rdi
    1b6c:	66 0f 6f 54 24 40    	movdqa 0x40(%rsp),%xmm2
    1b72:	66 0f 6f 5c 24 60    	movdqa 0x60(%rsp),%xmm3
    1b78:	b9 20 00 00 00       	mov    $0x20,%ecx
    1b7d:	66 0f 6f a4 24 80 00 	movdqa 0x80(%rsp),%xmm4
    1b84:	00 00 
    1b86:	0f 11 03             	movups %xmm0,(%rbx)
    1b89:	66 0f 6f ac 24 a0 00 	movdqa 0xa0(%rsp),%xmm5
    1b90:	00 00 
    1b92:	66 0f 6f b4 24 c0 00 	movdqa 0xc0(%rsp),%xmm6
    1b99:	00 00 
    1b9b:	0f 11 4b 10          	movups %xmm1,0x10(%rbx)
    1b9f:	66 0f 6f bc 24 e0 00 	movdqa 0xe0(%rsp),%xmm7
    1ba6:	00 00 
    1ba8:	0f 11 53 20          	movups %xmm2,0x20(%rbx)
    1bac:	0f 11 5b 30          	movups %xmm3,0x30(%rbx)
    1bb0:	0f 11 63 40          	movups %xmm4,0x40(%rbx)
    1bb4:	f3 48 ab             	rep stos %rax,%es:(%rdi)
    1bb7:	0f 11 6b 50          	movups %xmm5,0x50(%rbx)
    1bbb:	0f 11 73 60          	movups %xmm6,0x60(%rbx)
    1bbf:	0f 11 7b 70          	movups %xmm7,0x70(%rbx)
    1bc3:	b8 01 00 00 00       	mov    $0x1,%eax
    1bc8:	48 8b 94 24 08 01 00 	mov    0x108(%rsp),%rdx
    1bcf:	00 
    1bd0:	64 48 2b 14 25 28 00 	sub    %fs:0x28,%rdx
    1bd7:	00 00 
    1bd9:	75 73                	jne    1c4e <a15_sm3i_consume+0x17e>
    1bdb:	48 81 c4 18 01 00 00 	add    $0x118,%rsp
    1be2:	5b                   	pop    %rbx
    1be3:	5d                   	pop    %rbp
    1be4:	c3                   	ret    
    1be5:	0f 1f 00             	nopl   (%rax)
    1be8:	48 89 f2             	mov    %rsi,%rdx
    1beb:	48 29 fa             	sub    %rdi,%rdx
    1bee:	48 81 fa ff 08 00 00 	cmp    $0x8ff,%rdx
    1bf5:	0f 87 25 ff ff ff    	ja     1b20 <a15_sm3i_consume+0x50>
    1bfb:	eb cb                	jmp    1bc8 <a15_sm3i_consume+0xf8>
    1bfd:	0f 1f 00             	nopl   (%rax)
    1c00:	31 c0                	xor    %eax,%eax
    1c02:	eb c4                	jmp    1bc8 <a15_sm3i_consume+0xf8>
    1c04:	0f 1f 40 00          	nopl   0x0(%rax)
    1c08:	48 8d 7b 08          	lea    0x8(%rbx),%rdi
    1c0c:	48 c7 03 00 00 00 00 	movq   $0x0,(%rbx)
    1c13:	31 c0                	xor    %eax,%eax
    1c15:	48 83 e7 f8          	and    $0xfffffffffffffff8,%rdi
    1c19:	48 c7 43 78 00 00 00 	movq   $0x0,0x78(%rbx)
    1c20:	00 
    1c21:	48 29 fb             	sub    %rdi,%rbx
    1c24:	8d 8b 80 00 00 00    	lea    0x80(%rbx),%ecx
    1c2a:	c1 e9 03             	shr    $0x3,%ecx
    1c2d:	f3 48 ab             	rep stos %rax,%es:(%rdi)
    1c30:	eb 96                	jmp    1bc8 <a15_sm3i_consume+0xf8>
    1c32:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1c38:	48 8b 4f 70          	mov    0x70(%rdi),%rcx
    1c3c:	48 89 f2             	mov    %rsi,%rdx
    1c3f:	49 89 e8             	mov    %rbp,%r8
    1c42:	31 f6                	xor    %esi,%esi
    1c44:	e8 d7 ec ff ff       	call   920 <rounds8>
    1c49:	e9 0e ff ff ff       	jmp    1b5c <a15_sm3i_consume+0x8c>
    1c4e:	e8 00 00 00 00       	call   1c53 <a15_sm3i_consume+0x183>
    1c53:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
    1c5a:	00 00 00 00 
    1c5e:	66 90                	xchg   %ax,%ax

0000000000001c60 <a15_sm3i_advance>:
    1c60:	f3 0f 1e fa          	endbr64 
    1c64:	48 85 ff             	test   %rdi,%rdi
    1c67:	0f 84 a3 02 00 00    	je     1f10 <a15_sm3i_advance+0x2b0>
    1c6d:	8b 47 68             	mov    0x68(%rdi),%eax
    1c70:	49 89 f8             	mov    %rdi,%r8
    1c73:	85 c0                	test   %eax,%eax
    1c75:	0f 84 65 02 00 00    	je     1ee0 <a15_sm3i_advance+0x280>
    1c7b:	8b 47 54             	mov    0x54(%rdi),%eax
    1c7e:	8b 57 58             	mov    0x58(%rdi),%edx
    1c81:	39 d0                	cmp    %edx,%eax
    1c83:	0f 83 57 02 00 00    	jae    1ee0 <a15_sm3i_advance+0x280>
    1c89:	83 c0 01             	add    $0x1,%eax
    1c8c:	39 c2                	cmp    %eax,%edx
    1c8e:	0f 84 4c 02 00 00    	je     1ee0 <a15_sm3i_advance+0x280>
    1c94:	48 83 ec 08          	sub    $0x8,%rsp
    1c98:	8b 4f 60             	mov    0x60(%rdi),%ecx
    1c9b:	89 47 54             	mov    %eax,0x54(%rdi)
    1c9e:	8d 51 fe             	lea    -0x2(%rcx),%edx
    1ca1:	83 e2 fd             	and    $0xfffffffd,%edx
    1ca4:	0f 85 69 02 00 00    	jne    1f13 <a15_sm3i_advance+0x2b3>
    1caa:	89 c2                	mov    %eax,%edx
    1cac:	83 e2 01             	and    $0x1,%edx
    1caf:	0f 85 65 02 00 00    	jne    1f1a <a15_sm3i_advance+0x2ba>
    1cb5:	0f 1f 00             	nopl   (%rax)
    1cb8:	d1 e8                	shr    %eax
    1cba:	83 c2 01             	add    $0x1,%edx
    1cbd:	a8 01                	test   $0x1,%al
    1cbf:	74 f7                	je     1cb8 <a15_sm3i_advance+0x58>
    1cc1:	48 89 d0             	mov    %rdx,%rax
    1cc4:	48 c1 e0 04          	shl    $0x4,%rax
    1cc8:	48 01 d0             	add    %rdx,%rax
    1ccb:	48 c1 e0 04          	shl    $0x4,%rax
    1ccf:	49 8b 78 78          	mov    0x78(%r8),%rdi
    1cd3:	48 8d 34 07          	lea    (%rdi,%rax,1),%rsi
    1cd7:	83 f9 02             	cmp    $0x2,%ecx
    1cda:	0f 84 41 02 00 00    	je     1f21 <a15_sm3i_advance+0x2c1>
    1ce0:	49 8d 90 80 00 00 00 	lea    0x80(%r8),%rdx
    1ce7:	48 8d 4c 07 04       	lea    0x4(%rdi,%rax,1),%rcx
    1cec:	48 89 d0             	mov    %rdx,%rax
    1cef:	48 29 c8             	sub    %rcx,%rax
    1cf2:	48 83 f8 08          	cmp    $0x8,%rax
    1cf6:	0f 86 38 02 00 00    	jbe    1f34 <a15_sm3i_advance+0x2d4>
    1cfc:	f3 41 0f 6f 80 80 00 	movdqu 0x80(%r8),%xmm0
    1d03:	00 00 
    1d05:	f3 0f 6f 0e          	movdqu (%rsi),%xmm1
    1d09:	66 0f ef c1          	pxor   %xmm1,%xmm0
    1d0d:	41 0f 11 80 80 00 00 	movups %xmm0,0x80(%r8)
    1d14:	00 
    1d15:	f3 0f 6f 56 10       	movdqu 0x10(%rsi),%xmm2
    1d1a:	f3 41 0f 6f 80 90 00 	movdqu 0x90(%r8),%xmm0
    1d21:	00 00 
    1d23:	66 0f ef c2          	pxor   %xmm2,%xmm0
    1d27:	41 0f 11 80 90 00 00 	movups %xmm0,0x90(%r8)
    1d2e:	00 
    1d2f:	f3 0f 6f 5e 20       	movdqu 0x20(%rsi),%xmm3
    1d34:	f3 41 0f 6f 80 a0 00 	movdqu 0xa0(%r8),%xmm0
    1d3b:	00 00 
    1d3d:	66 0f ef c3          	pxor   %xmm3,%xmm0
    1d41:	41 0f 11 80 a0 00 00 	movups %xmm0,0xa0(%r8)
    1d48:	00 
    1d49:	f3 0f 6f 66 30       	movdqu 0x30(%rsi),%xmm4
    1d4e:	f3 41 0f 6f 80 b0 00 	movdqu 0xb0(%r8),%xmm0
    1d55:	00 00 
    1d57:	66 0f ef c4          	pxor   %xmm4,%xmm0
    1d5b:	41 0f 11 80 b0 00 00 	movups %xmm0,0xb0(%r8)
    1d62:	00 
    1d63:	f3 0f 6f 6e 40       	movdqu 0x40(%rsi),%xmm5
    1d68:	f3 41 0f 6f 80 c0 00 	movdqu 0xc0(%r8),%xmm0
    1d6f:	00 00 
    1d71:	66 0f ef c5          	pxor   %xmm5,%xmm0
    1d75:	41 0f 11 80 c0 00 00 	movups %xmm0,0xc0(%r8)
    1d7c:	00 
    1d7d:	f3 0f 6f 76 50       	movdqu 0x50(%rsi),%xmm6
    1d82:	f3 41 0f 6f 80 d0 00 	movdqu 0xd0(%r8),%xmm0
    1d89:	00 00 
    1d8b:	66 0f ef c6          	pxor   %xmm6,%xmm0
    1d8f:	41 0f 11 80 d0 00 00 	movups %xmm0,0xd0(%r8)
    1d96:	00 
    1d97:	f3 0f 6f 7e 60       	movdqu 0x60(%rsi),%xmm7
    1d9c:	f3 41 0f 6f 80 e0 00 	movdqu 0xe0(%r8),%xmm0
    1da3:	00 00 
    1da5:	66 0f ef c7          	pxor   %xmm7,%xmm0
    1da9:	41 0f 11 80 e0 00 00 	movups %xmm0,0xe0(%r8)
    1db0:	00 
    1db1:	f3 0f 6f 4e 70       	movdqu 0x70(%rsi),%xmm1
    1db6:	f3 41 0f 6f 80 f0 00 	movdqu 0xf0(%r8),%xmm0
    1dbd:	00 00 
    1dbf:	66 0f ef c1          	pxor   %xmm1,%xmm0
    1dc3:	41 0f 11 80 f0 00 00 	movups %xmm0,0xf0(%r8)
    1dca:	00 
    1dcb:	f3 0f 6f 96 80 00 00 	movdqu 0x80(%rsi),%xmm2
    1dd2:	00 
    1dd3:	f3 41 0f 6f 80 00 01 	movdqu 0x100(%r8),%xmm0
    1dda:	00 00 
    1ddc:	66 0f ef c2          	pxor   %xmm2,%xmm0
    1de0:	41 0f 11 80 00 01 00 	movups %xmm0,0x100(%r8)
    1de7:	00 
    1de8:	f3 0f 6f 9e 90 00 00 	movdqu 0x90(%rsi),%xmm3
    1def:	00 
    1df0:	f3 41 0f 6f 80 10 01 	movdqu 0x110(%r8),%xmm0
    1df7:	00 00 
    1df9:	66 0f ef c3          	pxor   %xmm3,%xmm0
    1dfd:	41 0f 11 80 10 01 00 	movups %xmm0,0x110(%r8)
    1e04:	00 
    1e05:	f3 0f 6f a6 a0 00 00 	movdqu 0xa0(%rsi),%xmm4
    1e0c:	00 
    1e0d:	f3 41 0f 6f 80 20 01 	movdqu 0x120(%r8),%xmm0
    1e14:	00 00 
    1e16:	66 0f ef c4          	pxor   %xmm4,%xmm0
    1e1a:	41 0f 11 80 20 01 00 	movups %xmm0,0x120(%r8)
    1e21:	00 
    1e22:	f3 0f 6f ae b0 00 00 	movdqu 0xb0(%rsi),%xmm5
    1e29:	00 
    1e2a:	f3 41 0f 6f 80 30 01 	movdqu 0x130(%r8),%xmm0
    1e31:	00 00 
    1e33:	f3 41 0f 6f 98 80 01 	movdqu 0x180(%r8),%xmm3
    1e3a:	00 00 
    1e3c:	66 0f ef c5          	pxor   %xmm5,%xmm0
    1e40:	41 0f 11 80 30 01 00 	movups %xmm0,0x130(%r8)
    1e47:	00 
    1e48:	f3 0f 6f b6 c0 00 00 	movdqu 0xc0(%rsi),%xmm6
    1e4f:	00 
    1e50:	f3 41 0f 6f 80 40 01 	movdqu 0x140(%r8),%xmm0
    1e57:	00 00 
    1e59:	66 0f ef c6          	pxor   %xmm6,%xmm0
    1e5d:	41 0f 11 80 40 01 00 	movups %xmm0,0x140(%r8)
    1e64:	00 
    1e65:	f3 0f 6f be d0 00 00 	movdqu 0xd0(%rsi),%xmm7
    1e6c:	00 
    1e6d:	f3 41 0f 6f 80 50 01 	movdqu 0x150(%r8),%xmm0
    1e74:	00 00 
    1e76:	66 0f ef c7          	pxor   %xmm7,%xmm0
    1e7a:	41 0f 11 80 50 01 00 	movups %xmm0,0x150(%r8)
    1e81:	00 
    1e82:	f3 0f 6f 8e e0 00 00 	movdqu 0xe0(%rsi),%xmm1
    1e89:	00 
    1e8a:	f3 41 0f 6f 80 60 01 	movdqu 0x160(%r8),%xmm0
    1e91:	00 00 
    1e93:	66 0f ef c1          	pxor   %xmm1,%xmm0
    1e97:	41 0f 11 80 60 01 00 	movups %xmm0,0x160(%r8)
    1e9e:	00 
    1e9f:	f3 0f 6f 96 f0 00 00 	movdqu 0xf0(%rsi),%xmm2
    1ea6:	00 
    1ea7:	f3 41 0f 6f 80 70 01 	movdqu 0x170(%r8),%xmm0
    1eae:	00 00 
    1eb0:	66 0f ef c2          	pxor   %xmm2,%xmm0
    1eb4:	41 0f 11 80 70 01 00 	movups %xmm0,0x170(%r8)
    1ebb:	00 
    1ebc:	f3 0f 6f 86 00 01 00 	movdqu 0x100(%rsi),%xmm0
    1ec3:	00 
    1ec4:	66 0f ef c3          	pxor   %xmm3,%xmm0
    1ec8:	41 0f 11 80 80 01 00 	movups %xmm0,0x180(%r8)
    1ecf:	00 
    1ed0:	b8 01 00 00 00       	mov    $0x1,%eax
    1ed5:	48 83 c4 08          	add    $0x8,%rsp
    1ed9:	c3                   	ret    
    1eda:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1ee0:	49 8d 78 08          	lea    0x8(%r8),%rdi
    1ee4:	4c 89 c1             	mov    %r8,%rcx
    1ee7:	31 c0                	xor    %eax,%eax
    1ee9:	49 c7 00 00 00 00 00 	movq   $0x0,(%r8)
    1ef0:	49 c7 80 f8 08 00 00 	movq   $0x0,0x8f8(%r8)
    1ef7:	00 00 00 00 
    1efb:	48 83 e7 f8          	and    $0xfffffffffffffff8,%rdi
    1eff:	48 29 f9             	sub    %rdi,%rcx
    1f02:	81 c1 00 09 00 00    	add    $0x900,%ecx
    1f08:	c1 e9 03             	shr    $0x3,%ecx
    1f0b:	f3 48 ab             	rep stos %rax,%es:(%rdi)
    1f0e:	c3                   	ret    
    1f0f:	90                   	nop
    1f10:	31 c0                	xor    %eax,%eax
    1f12:	c3                   	ret    
    1f13:	e8 08 f3 ff ff       	call   1220 <build_schedule>
    1f18:	eb b6                	jmp    1ed0 <a15_sm3i_advance+0x270>
    1f1a:	31 c0                	xor    %eax,%eax
    1f1c:	e9 ae fd ff ff       	jmp    1ccf <a15_sm3i_advance+0x6f>
    1f21:	49 8d b8 80 00 00 00 	lea    0x80(%r8),%rdi
    1f28:	e8 53 e3 ff ff       	call   280 <update8>
    1f2d:	b8 01 00 00 00       	mov    $0x1,%eax
    1f32:	eb a1                	jmp    1ed5 <a15_sm3i_advance+0x275>
    1f34:	31 c0                	xor    %eax,%eax
    1f36:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
    1f3d:	00 00 00 
    1f40:	8b 14 06             	mov    (%rsi,%rax,1),%edx
    1f43:	41 31 94 00 80 00 00 	xor    %edx,0x80(%r8,%rax,1)
    1f4a:	00 
    1f4b:	48 83 c0 04          	add    $0x4,%rax
    1f4f:	48 3d 10 01 00 00    	cmp    $0x110,%rax
    1f55:	75 e9                	jne    1f40 <a15_sm3i_advance+0x2e0>
    1f57:	e9 74 ff ff ff       	jmp    1ed0 <a15_sm3i_advance+0x270>
    1f5c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000001f60 <a15_sm3i_next>:
    1f60:	f3 0f 1e fa          	endbr64 
    1f64:	41 54                	push   %r12
    1f66:	55                   	push   %rbp
    1f67:	53                   	push   %rbx
    1f68:	48 81 ec 10 01 00 00 	sub    $0x110,%rsp
    1f6f:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    1f76:	00 00 
    1f78:	48 89 84 24 08 01 00 	mov    %rax,0x108(%rsp)
    1f7f:	00 
    1f80:	31 c0                	xor    %eax,%eax
    1f82:	48 85 ff             	test   %rdi,%rdi
    1f85:	0f 84 4d 01 00 00    	je     20d8 <a15_sm3i_next+0x178>
    1f8b:	48 89 fd             	mov    %rdi,%rbp
    1f8e:	48 89 f3             	mov    %rsi,%rbx
    1f91:	48 85 f6             	test   %rsi,%rsi
    1f94:	0f 84 36 01 00 00    	je     20d0 <a15_sm3i_next+0x170>
    1f9a:	48 39 f7             	cmp    %rsi,%rdi
    1f9d:	0f 86 cd 00 00 00    	jbe    2070 <a15_sm3i_next+0x110>
    1fa3:	48 89 f8             	mov    %rdi,%rax
    1fa6:	48 29 f0             	sub    %rsi,%rax
    1fa9:	48 83 f8 7f          	cmp    $0x7f,%rax
    1fad:	0f 86 cf 00 00 00    	jbe    2082 <a15_sm3i_next+0x122>
    1fb3:	8b 45 68             	mov    0x68(%rbp),%eax
    1fb6:	85 c0                	test   %eax,%eax
    1fb8:	0f 84 22 01 00 00    	je     20e0 <a15_sm3i_next+0x180>
    1fbe:	8b 45 58             	mov    0x58(%rbp),%eax
    1fc1:	39 45 54             	cmp    %eax,0x54(%rbp)
    1fc4:	0f 83 16 01 00 00    	jae    20e0 <a15_sm3i_next+0x180>
    1fca:	8b 45 60             	mov    0x60(%rbp),%eax
    1fcd:	48 8d b5 80 00 00 00 	lea    0x80(%rbp),%rsi
    1fd4:	49 89 e4             	mov    %rsp,%r12
    1fd7:	83 e8 03             	sub    $0x3,%eax
    1fda:	83 f8 01             	cmp    $0x1,%eax
    1fdd:	0f 86 2d 01 00 00    	jbe    2110 <a15_sm3i_next+0x1b0>
    1fe3:	4d 89 e0             	mov    %r12,%r8
    1fe6:	31 c9                	xor    %ecx,%ecx
    1fe8:	31 d2                	xor    %edx,%edx
    1fea:	48 89 ef             	mov    %rbp,%rdi
    1fed:	e8 1e ed ff ff       	call   d10 <rounds8.constprop.0>
    1ff2:	66 0f 6f 04 24       	movdqa (%rsp),%xmm0
    1ff7:	66 0f 6f 4c 24 20    	movdqa 0x20(%rsp),%xmm1
    1ffd:	31 c0                	xor    %eax,%eax
    1fff:	4c 89 e7             	mov    %r12,%rdi
    2002:	66 0f 6f 54 24 40    	movdqa 0x40(%rsp),%xmm2
    2008:	66 0f 6f 5c 24 60    	movdqa 0x60(%rsp),%xmm3
    200e:	b9 20 00 00 00       	mov    $0x20,%ecx
    2013:	66 0f 6f a4 24 80 00 	movdqa 0x80(%rsp),%xmm4
    201a:	00 00 
    201c:	0f 11 03             	movups %xmm0,(%rbx)
    201f:	66 0f 6f ac 24 a0 00 	movdqa 0xa0(%rsp),%xmm5
    2026:	00 00 
    2028:	66 0f 6f b4 24 c0 00 	movdqa 0xc0(%rsp),%xmm6
    202f:	00 00 
    2031:	0f 11 4b 10          	movups %xmm1,0x10(%rbx)
    2035:	66 0f 6f bc 24 e0 00 	movdqa 0xe0(%rsp),%xmm7
    203c:	00 00 
    203e:	0f 11 53 20          	movups %xmm2,0x20(%rbx)
    2042:	f3 48 ab             	rep stos %rax,%es:(%rdi)
    2045:	0f 11 5b 30          	movups %xmm3,0x30(%rbx)
    2049:	0f 11 63 40          	movups %xmm4,0x40(%rbx)
    204d:	0f 11 6b 50          	movups %xmm5,0x50(%rbx)
    2051:	0f 11 73 60          	movups %xmm6,0x60(%rbx)
    2055:	0f 11 7b 70          	movups %xmm7,0x70(%rbx)
    2059:	48 89 ef             	mov    %rbp,%rdi
    205c:	e8 00 00 00 00       	call   2061 <a15_sm3i_next+0x101>
    2061:	b8 01 00 00 00       	mov    $0x1,%eax
    2066:	eb 49                	jmp    20b1 <a15_sm3i_next+0x151>
    2068:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    206f:	00 
    2070:	48 89 f0             	mov    %rsi,%rax
    2073:	48 29 f8             	sub    %rdi,%rax
    2076:	48 3d ff 08 00 00    	cmp    $0x8ff,%rax
    207c:	0f 87 31 ff ff ff    	ja     1fb3 <a15_sm3i_next+0x53>
    2082:	48 8d 7d 08          	lea    0x8(%rbp),%rdi
    2086:	48 89 e9             	mov    %rbp,%rcx
    2089:	31 c0                	xor    %eax,%eax
    208b:	48 c7 45 00 00 00 00 	movq   $0x0,0x0(%rbp)
    2092:	00 
    2093:	48 c7 85 f8 08 00 00 	movq   $0x0,0x8f8(%rbp)
    209a:	00 00 00 00 
    209e:	48 83 e7 f8          	and    $0xfffffffffffffff8,%rdi
    20a2:	48 29 f9             	sub    %rdi,%rcx
    20a5:	81 c1 00 09 00 00    	add    $0x900,%ecx
    20ab:	c1 e9 03             	shr    $0x3,%ecx
    20ae:	f3 48 ab             	rep stos %rax,%es:(%rdi)
    20b1:	48 8b 94 24 08 01 00 	mov    0x108(%rsp),%rdx
    20b8:	00 
    20b9:	64 48 2b 14 25 28 00 	sub    %fs:0x28,%rdx
    20c0:	00 00 
    20c2:	75 65                	jne    2129 <a15_sm3i_next+0x1c9>
    20c4:	48 81 c4 10 01 00 00 	add    $0x110,%rsp
    20cb:	5b                   	pop    %rbx
    20cc:	5d                   	pop    %rbp
    20cd:	41 5c                	pop    %r12
    20cf:	c3                   	ret    
    20d0:	48 85 ff             	test   %rdi,%rdi
    20d3:	75 ad                	jne    2082 <a15_sm3i_next+0x122>
    20d5:	0f 1f 00             	nopl   (%rax)
    20d8:	31 c0                	xor    %eax,%eax
    20da:	eb d5                	jmp    20b1 <a15_sm3i_next+0x151>
    20dc:	0f 1f 40 00          	nopl   0x0(%rax)
    20e0:	48 8d 7b 08          	lea    0x8(%rbx),%rdi
    20e4:	48 c7 03 00 00 00 00 	movq   $0x0,(%rbx)
    20eb:	31 c0                	xor    %eax,%eax
    20ed:	48 83 e7 f8          	and    $0xfffffffffffffff8,%rdi
    20f1:	48 c7 43 78 00 00 00 	movq   $0x0,0x78(%rbx)
    20f8:	00 
    20f9:	48 29 fb             	sub    %rdi,%rbx
    20fc:	8d 8b 80 00 00 00    	lea    0x80(%rbx),%ecx
    2102:	c1 e9 03             	shr    $0x3,%ecx
    2105:	f3 48 ab             	rep stos %rax,%es:(%rdi)
    2108:	e9 75 ff ff ff       	jmp    2082 <a15_sm3i_next+0x122>
    210d:	0f 1f 00             	nopl   (%rax)
    2110:	48 8b 4d 70          	mov    0x70(%rbp),%rcx
    2114:	48 89 f2             	mov    %rsi,%rdx
    2117:	4d 89 e0             	mov    %r12,%r8
    211a:	31 f6                	xor    %esi,%esi
    211c:	48 89 ef             	mov    %rbp,%rdi
    211f:	e8 fc e7 ff ff       	call   920 <rounds8>
    2124:	e9 c9 fe ff ff       	jmp    1ff2 <a15_sm3i_next+0x92>
    2129:	e8 00 00 00 00       	call   212e <a15_sm3i_next+0x1ce>
