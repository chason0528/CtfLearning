unsigned __int8 *__fastcall sub_400735(__int64 str_base, signed int len)
{
  int len_div3_mul4; // eax
  unsigned int len_unit_3; // [rsp+18h] [rbp-18h]
  int len_unit_4; // [rsp+1Ch] [rbp-14h]
  unsigned int i; // [rsp+1Ch] [rbp-14h]
  int last_number; // [rsp+20h] [rbp-10h]
  unsigned int len_div3_mul4_; // [rsp+24h] [rbp-Ch]
  unsigned __int8 *new_s; // [rsp+28h] [rbp-8h]

  last_number = len % 3;
  if ( len % 3 )
    len_div3_mul4 = 4 * (len / 3 + 1);
  else
    len_div3_mul4 = 4 * (len / 3);
  len_div3_mul4_ = len_div3_mul4;
  new_s = (unsigned __int8 *)malloc((unsigned int)(len_div3_mul4 + 1));
  memset(new_s, 0, len_div3_mul4_ + 1);
  len_unit_3 = 0;
  len_unit_4 = 0;
  while ( len_unit_3 < len )
  {
    if ( len_unit_3 + 2 >= len )                // 余出来的两位或一位
    {
      new_s[len_unit_4] = *(_BYTE *)(len_unit_3 + str_base) >> 2;
      if ( last_number == 1 )                   // 余数为1
      {
        new_s[len_unit_4 + 1] = 16 * (*(_BYTE *)(len_unit_3 + str_base) & 3) & 0x3F;
        new_s[len_unit_4 + 2] = 64;
        new_s[len_unit_4 + 3] = 64;
      }
      else if ( last_number == 2 )              // 余数为2
      {
        new_s[len_unit_4 + 1] = 16 * (*(_BYTE *)(len_unit_3 + str_base) & 3) | (*(_BYTE *)(len_unit_3 + 1 + str_base) >> 4);
        new_s[len_unit_4 + 2] = 4 * (*(_BYTE *)(len_unit_3 + 1 + str_base) & 0xF) & 0x3F;
        new_s[len_unit_4 + 3] = 64;
        break;
      }
    }
    new_s[len_unit_4] = *(_BYTE *)(len_unit_3 + str_base) >> 2;
    new_s[len_unit_4 + 1] = 16 * (*(_BYTE *)(len_unit_3 + str_base) & 3) | (*(_BYTE *)(len_unit_3 + 1 + str_base) >> 4);
    new_s[len_unit_4 + 2] = 4 * (*(_BYTE *)(len_unit_3 + 1 + str_base) & 0xF) | (*(_BYTE *)(len_unit_3 + 2 + str_base) >> 6);
    new_s[len_unit_4 + 3] = *(_BYTE *)(len_unit_3 + 2 + str_base) & 0x3F;
    len_unit_3 += 3;
    len_unit_4 += 4;
  }
  for ( i = 0; i < len_div3_mul4_; ++i )
    new_s[i] = off_602068[new_s[i]];
  return new_s;
}
